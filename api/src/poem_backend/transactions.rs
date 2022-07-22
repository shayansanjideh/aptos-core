// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use super::accept_type::{parse_accept, AcceptType};
use super::page::Page;
use super::{
    ApiTags, AptosErrorResponse, BasicErrorWith404, BasicResponse, BasicResponseStatus,
    BasicResultWith404, InternalError,
};
use super::{AptosErrorCode, AptosPost, BadRequestError, InsufficientStorageError};
use crate::context::Context;
use crate::failpoint::fail_point_poem;
use crate::{generate_error_response, generate_success_response};
use anyhow::Context as AnyhowContext;
use aptos_api_types::{
    AsConverter, LedgerInfo, Transaction, TransactionOnChainData, UserTransactionRequest,
};
use aptos_types::mempool_status::MempoolStatusCode;
use aptos_types::transaction::SignedTransaction;
use poem::web::Accept;
use poem_openapi::param::Query;
use poem_openapi::OpenApi;

generate_success_response!(SubmitTransactionResponse, (202, Accepted));
generate_error_response!(
    SubmitTransactionError,
    (400, BadRequest),
    (500, Internal),
    (507, InsufficientStorage)
);

type SubmitTransactionResult<T> =
    poem::Result<SubmitTransactionResponse<T>, SubmitTransactionError>;

pub struct TransactionsApi {
    pub context: Arc<Context>,
}

#[OpenApi]
impl TransactionsApi {
    /// Get transactions
    ///
    /// todo
    #[oai(
        path = "/transactions",
        method = "get",
        operation_id = "get_transactions",
        tag = "ApiTags::General"
    )]
    async fn get_transactions(
        &self,
        accept: Accept,
        start: Query<Option<u64>>,
        limit: Query<Option<u16>>,
    ) -> BasicResultWith404<Vec<Transaction>> {
        fail_point_poem::<BasicErrorWith404>("endppoint_get_transactions")?;
        let accept_type = parse_accept::<BasicErrorWith404>(&accept)?;
        let page = Page::new(start.0, limit.0);
        self.list(&accept_type, page)
    }

    // TODO: Despite what the old API spec says, this endpoint does not return
    // a PendingTransaction, it returns a Transaction where the enum variant
    // used happens to always be a PendingTransaction. Change this endpoint and
    // underlying code to actually return a PendingTransaction directly.
    //
    // TODO: The previous spec says this function can return 413 and 415 but
    // none of the code actually does that. I imagine it should though,
    // investigate that.
    #[oai(
        path = "/transactions",
        method = "post",
        operation_id = "submit_transaction",
        tag = "ApiTags::General"
    )]
    async fn submit_transaction(
        &self,
        accept: Accept,
        user_transaction_request: AptosPost<UserTransactionRequest>,
    ) -> SubmitTransactionResult<Transaction> {
        fail_point_poem::<SubmitTransactionError>("endppoint_submit_transaction")?;
        let accept_type = parse_accept::<SubmitTransactionError>(&accept)?;
        self.create_from_request(&accept_type, user_transaction_request.take())
            .await
    }
}

impl TransactionsApi {
    fn list(&self, accept_type: &AcceptType, page: Page) -> BasicResultWith404<Vec<Transaction>> {
        let latest_ledger_info = self
            .context
            .get_latest_ledger_info_poem::<BasicErrorWith404>()?;
        let ledger_version = latest_ledger_info.version();
        let limit = page.limit::<BasicErrorWith404>()?;
        let last_page_start = if ledger_version > (limit as u64) {
            ledger_version - (limit as u64)
        } else {
            0
        };
        let start_version = page.start::<BasicErrorWith404>(last_page_start, ledger_version)?;

        let data = self
            .context
            .get_transactions(start_version, limit, ledger_version)
            .context("Failed to read raw transactions from storage")
            .map_err(BasicErrorWith404::internal)
            .map_err(|e| e.error_code(AptosErrorCode::InvalidBcsInStorageError))?;

        self.render_transactions(data, accept_type, &latest_ledger_info)
    }

    fn render_transactions(
        &self,
        data: Vec<TransactionOnChainData>,
        accept_type: &AcceptType,
        latest_ledger_info: &LedgerInfo,
    ) -> BasicResultWith404<Vec<Transaction>> {
        if data.is_empty() {
            let data: Vec<Transaction> = vec![];
            return BasicResponse::try_from_rust_value::<BasicErrorWith404>((
                data,
                latest_ledger_info,
                BasicResponseStatus::Ok,
                accept_type,
            ));
        }

        let resolver = self.context.move_resolver_poem::<BasicErrorWith404>()?;
        let converter = resolver.as_converter();
        let txns: Vec<Transaction> = data
            .into_iter()
            .map(|t| {
                let version = t.version;
                let timestamp = self.context.get_block_timestamp(version)?;
                let txn = converter.try_into_onchain_transaction(timestamp, t)?;
                Ok(txn)
            })
            .collect::<Result<_, anyhow::Error>>()
            .context("Failed to convert transaction data from storage")
            .map_err(BasicErrorWith404::internal)?;

        BasicResponse::try_from_rust_value((
            txns,
            latest_ledger_info,
            BasicResponseStatus::Ok,
            accept_type,
        ))
    }

    async fn create_from_request(
        &self,
        accept_type: &AcceptType,
        req: UserTransactionRequest,
    ) -> SubmitTransactionResult<Transaction> {
        let txn = self
            .context
            .move_resolver_poem::<SubmitTransactionError>()?
            .as_converter()
            .try_into_signed_transaction(req, self.context.chain_id())
            .context("Failed to create SignedTransaction from UserTransactionRequest")
            .map_err(SubmitTransactionError::bad_request)?;
        self.create(accept_type, txn).await
    }

    async fn create(
        &self,
        accept_type: &AcceptType,
        txn: SignedTransaction,
    ) -> SubmitTransactionResult<Transaction> {
        let ledger_info = self
            .context
            .get_latest_ledger_info_poem::<SubmitTransactionError>()?;
        let (mempool_status, vm_status_opt) = self
            .context
            .submit_transaction(txn.clone())
            .await
            .context("Mempool failed to initially evaluate submitted transaction")
            .map_err(SubmitTransactionError::internal)?;
        match mempool_status.code {
            MempoolStatusCode::Accepted => {
                let resolver = self
                    .context
                    .move_resolver_poem::<SubmitTransactionError>()?;
                let pending_txn = resolver
                    .as_converter()
                    .try_into_pending_transaction(txn)
                    .context("Failed to build PendingTransaction from mempool response, even though it said the request was accepted")
                    .map_err(SubmitTransactionError::internal)?;
                SubmitTransactionResponse::try_from_rust_value((
                    pending_txn,
                    &ledger_info,
                    SubmitTransactionResponseStatus::Accepted,
                    accept_type,
                ))
            }
            MempoolStatusCode::MempoolIsFull => Err(
                SubmitTransactionError::insufficient_storage_str(&mempool_status.message),
            ),
            MempoolStatusCode::VmError => Err(SubmitTransactionError::bad_request_str(&format!(
                "invalid transaction: {}",
                vm_status_opt
                    .map(|s| format!("{:?}", s))
                    .unwrap_or_else(|| "UNKNOWN".to_owned())
            ))),
            _ => Err(SubmitTransactionError::bad_request_str(&format!(
                "transaction is rejected: {}",
                mempool_status,
            ))),
        }
    }
}
