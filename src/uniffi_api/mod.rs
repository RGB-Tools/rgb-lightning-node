pub(crate) mod state;
mod types;

use std::str::FromStr;

use crate::sdk;
use crate::{NodeConfig, NodeHandle};

use state::{
    block_on_app, block_on_sdk, clear_uniffi_node_handle, get_uniffi_app_state,
    is_uniffi_app_state_initialized, set_uniffi_node_handle,
};
pub(crate) use state::{clear_uniffi_app_state, set_uniffi_app_state};
pub use types::*;

pub fn uniffi_healthcheck() -> String {
    "rgb_lightning_node_uniffi_ready".to_string()
}

pub fn uniffi_is_initialized() -> bool {
    is_uniffi_app_state_initialized()
}

fn network_from_str(network: &str) -> Result<rgb_lib::BitcoinNetwork, RlnError> {
    match network.to_lowercase().as_str() {
        "mainnet" => Ok(rgb_lib::BitcoinNetwork::Mainnet),
        "testnet" => Ok(rgb_lib::BitcoinNetwork::Testnet),
        "testnet4" => Ok(rgb_lib::BitcoinNetwork::Testnet4),
        "signet" => Ok(rgb_lib::BitcoinNetwork::Signet),
        "regtest" => Ok(rgb_lib::BitcoinNetwork::Regtest),
        _ => Err(RlnError::InvalidRequest),
    }
}

fn handle_from_request(request: SdkInitRequest) -> Result<NodeHandle, RlnError> {
    let network = network_from_str(&request.network)?;
    let config = NodeConfig {
        storage_dir_path: std::path::PathBuf::from(request.storage_dir_path),
        daemon_listening_port: request.daemon_listening_port,
        ldk_peer_listening_port: request.ldk_peer_listening_port,
        network,
        max_media_upload_size_mb: request.max_media_upload_size_mb,
        root_public_key: None,
        enable_virtual_channels_v0: request.enable_virtual_channels_v0.unwrap_or(false),
        virtual_peer_pubkeys: request.virtual_peer_pubkeys.unwrap_or_default(),
    };
    block_on_app(NodeHandle::new(config))
}

fn send_rgb_from_state(
    state: std::sync::Arc<crate::utils::AppState>,
    request: SendRgbRequest,
) -> Result<SendRgbResponse, RlnError> {
    let sdk_request = sdk::SendRgbRequestData {
        donation: request.donation,
        fee_rate: request.fee_rate,
        min_confirmations: request.min_confirmations,
        skip_sync: request.skip_sync,
        recipient_groups: request
            .recipient_groups
            .into_iter()
            .map(|group| sdk::AssetRecipientsInput {
                asset_id: group.asset_id.to_string(),
                recipients: group
                    .recipients
                    .into_iter()
                    .map(|r| sdk::RecipientInput {
                        recipient_id: r.recipient_id.0,
                        witness_data: r.witness_data.map(|w| sdk::WitnessDataInput {
                            amount_sat: w.amount_sat,
                            blinding: w.blinding,
                        }),
                        assignment_kind: match r.assignment_kind {
                            AssignmentKind::Fungible => sdk::AssignmentKindData::Fungible,
                            AssignmentKind::NonFungible => sdk::AssignmentKindData::NonFungible,
                            AssignmentKind::InflationRight => {
                                sdk::AssignmentKindData::InflationRight
                            }
                            AssignmentKind::ReplaceRight => sdk::AssignmentKindData::ReplaceRight,
                            AssignmentKind::Any => sdk::AssignmentKindData::Any,
                        },
                        assignment_amount: r.assignment_amount,
                        transport_endpoints: r
                            .transport_endpoints
                            .into_iter()
                            .map(|e| e.0)
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
    };

    let data = block_on_sdk(sdk::send_rgb_from_groups(state, sdk_request))?;
    let txid = Txid::from_str(&data.txid).map_err(|_| RlnError::Internal)?;
    Ok(SendRgbResponse {
        txid,
        batch_transfer_idx: data.batch_transfer_idx,
    })
}

fn map_payment_data(data: crate::sdk::PaymentData) -> Result<Payment, RlnError> {
    let payee_pubkey = PublicKey::from_str(&data.payee_pubkey).map_err(|_| RlnError::Internal)?;
    let asset_id = match data.asset_id {
        Some(asset_id) => Some(ContractId::from_str(&asset_id).map_err(|_| RlnError::Internal)?),
        None => None,
    };
    let payment_hash = <PaymentHash as UniffiCustomTypeConverter>::into_custom(data.payment_hash)
        .map_err(|_| RlnError::Internal)?;
    let status = match data.status {
        crate::sdk::HtlcStatus::Pending => HtlcStatus::Pending,
        crate::sdk::HtlcStatus::Succeeded => HtlcStatus::Succeeded,
        crate::sdk::HtlcStatus::Failed => HtlcStatus::Failed,
    };

    Ok(Payment {
        amt_msat: data.amt_msat,
        asset_amount: data.asset_amount,
        asset_id,
        payment_hash,
        inbound: data.inbound,
        status,
        created_at: data.created_at,
        updated_at: data.updated_at,
        payee_pubkey,
        preimage: data.preimage,
    })
}

fn map_swap_data(data: crate::sdk::SwapViewData) -> Result<Swap, RlnError> {
    let from_asset = match data.from_asset {
        Some(asset_id) => Some(ContractId::from_str(&asset_id).map_err(|_| RlnError::Internal)?),
        None => None,
    };
    let to_asset = match data.to_asset {
        Some(asset_id) => Some(ContractId::from_str(&asset_id).map_err(|_| RlnError::Internal)?),
        None => None,
    };
    let payment_hash = <PaymentHash as UniffiCustomTypeConverter>::into_custom(data.payment_hash)
        .map_err(|_| RlnError::Internal)?;
    let status = match data.status {
        crate::sdk::SwapStatus::Waiting => SwapStatus::Waiting,
        crate::sdk::SwapStatus::Pending => SwapStatus::Pending,
        crate::sdk::SwapStatus::Succeeded => SwapStatus::Succeeded,
        crate::sdk::SwapStatus::Expired => SwapStatus::Expired,
        crate::sdk::SwapStatus::Failed => SwapStatus::Failed,
    };

    Ok(Swap {
        qty_from: data.qty_from,
        qty_to: data.qty_to,
        from_asset,
        to_asset,
        payment_hash,
        status,
        requested_at: data.requested_at,
        initiated_at: data.initiated_at,
        expires_at: data.expires_at,
        completed_at: data.completed_at,
    })
}

fn map_asset_balance_data(data: crate::sdk::AssetBalanceData) -> AssetBalanceInfo {
    AssetBalanceInfo {
        settled: data.settled,
        future: data.future,
        spendable: data.spendable,
        offchain_outbound: data.offchain_outbound,
        offchain_inbound: data.offchain_inbound,
    }
}

fn map_asset_balance(data: crate::sdk::AssetBalance) -> AssetBalanceInfo {
    AssetBalanceInfo {
        settled: data.settled,
        future: data.future,
        spendable: data.spendable,
        offchain_outbound: data.offchain_outbound,
        offchain_inbound: data.offchain_inbound,
    }
}

fn map_media(data: crate::sdk::Media) -> Media {
    Media {
        file_path: data.file_path,
        digest: data.digest,
        mime: data.mime,
    }
}

fn map_token(data: crate::sdk::Token) -> Token {
    Token {
        index: data.index,
        ticker: data.ticker,
        name: data.name,
        details: data.details,
        embedded_media: data.embedded_media.map(|m| EmbeddedMedia {
            mime: m.mime,
            data: m.data,
        }),
        media: data.media.map(map_media),
        attachments: data
            .attachments
            .into_iter()
            .map(|(k, v)| MediaAttachment {
                key: k,
                media: map_media(v),
            })
            .collect(),
        reserves: data.reserves.map(|r| ProofOfReserves {
            utxo: r.utxo,
            proof: r.proof,
        }),
    }
}

impl SdkNode {
    pub fn create(request: SdkInitRequest) -> Result<Self, RlnError> {
        let handle = handle_from_request(request)?;
        Ok(Self { handle })
    }

    pub fn shutdown(&self) {
        let handle = self.handle.clone();
        let _ = block_on_sdk(async move {
            handle.shutdown().await;
            Ok::<(), crate::error::APIError>(())
        });
    }

    pub fn init(&self, password: String, mnemonic: Option<String>) -> Result<String, RlnError> {
        let state = self.handle.app_state();
        let response = block_on_sdk(sdk::init(state, password, mnemonic))?;
        Ok(response.mnemonic)
    }

    pub fn unlock(&self, request: SdkUnlockRequest) -> Result<(), RlnError> {
        let state = self.handle.app_state();
        block_on_sdk(sdk::unlock(
            state,
            sdk::UnlockRequest {
                password: request.password,
                bitcoind_rpc_username: request.bitcoind_rpc_username,
                bitcoind_rpc_password: request.bitcoind_rpc_password,
                bitcoind_rpc_host: request.bitcoind_rpc_host,
                bitcoind_rpc_port: request.bitcoind_rpc_port,
                indexer_url: request.indexer_url,
                proxy_endpoint: request.proxy_endpoint,
                announce_addresses: request.announce_addresses,
                announce_alias: request.announce_alias,
            },
        ))?;
        Ok(())
    }

    pub fn connectpeer(&self, peer_pubkey_and_addr: String) -> Result<(), RlnError> {
        let state = self.handle.app_state();
        block_on_sdk(sdk::connect_peer(state, peer_pubkey_and_addr))?;
        Ok(())
    }

    pub fn disconnectpeer(&self, request: SdkDisconnectPeerRequest) -> Result<(), RlnError> {
        let state = self.handle.app_state();
        block_on_sdk(sdk::disconnect_peer(
            state,
            sdk::DisconnectPeerRequestData {
                peer_pubkey: request.peer_pubkey.to_string(),
            },
        ))?;
        Ok(())
    }

    pub fn closechannel(&self, request: SdkCloseChannelRequest) -> Result<(), RlnError> {
        use bitcoin::hex::DisplayHex;

        let state = self.handle.app_state();
        block_on_sdk(sdk::close_channel(
            state,
            sdk::CloseChannelRequestData {
                channel_id: request.channel_id.0.as_hex().to_string(),
                peer_pubkey: request.peer_pubkey.to_string(),
                force: request.force,
            },
        ))?;
        Ok(())
    }

    pub fn createutxos(&self, request: SdkCreateUtxosRequest) -> Result<(), RlnError> {
        let state = self.handle.app_state();
        block_on_sdk(sdk::create_utxos(
            state,
            sdk::CreateUtxosRequestData {
                up_to: request.up_to,
                num: request.num,
                size: request.size,
                fee_rate: request.fee_rate,
                skip_sync: request.skip_sync,
            },
        ))?;
        Ok(())
    }

    pub fn issueassetnia(&self, request: SdkIssueAssetNiaRequest) -> Result<AssetNia, RlnError> {
        let state = self.handle.app_state();
        let asset = block_on_sdk(sdk::issue_asset_nia(
            state,
            sdk::IssueAssetNiaRequestData {
                amounts: request.amounts,
                ticker: request.ticker,
                name: request.name,
                precision: request.precision,
            },
        ))?;

        Ok(AssetNia {
            asset_id: ContractId::from_str(&asset.asset_id).map_err(|_| RlnError::Internal)?,
            ticker: asset.ticker,
            name: asset.name,
            details: asset.details,
            precision: asset.precision,
            issued_supply: asset.issued_supply,
            timestamp: asset.timestamp,
            added_at: asset.added_at,
            balance: map_asset_balance(asset.balance),
            media: asset.media.map(map_media),
        })
    }

    pub fn issueassetcfa(&self, request: SdkIssueAssetCfaRequest) -> Result<AssetCfa, RlnError> {
        let state = self.handle.app_state();
        let asset = block_on_sdk(sdk::issue_asset_cfa(
            state,
            sdk::IssueAssetCfaRequestData {
                amounts: request.amounts,
                name: request.name,
                details: request.details,
                precision: request.precision,
                file_digest: request.file_digest,
            },
        ))?;

        Ok(AssetCfa {
            asset_id: ContractId::from_str(&asset.asset_id).map_err(|_| RlnError::Internal)?,
            name: asset.name,
            details: asset.details,
            precision: asset.precision,
            issued_supply: asset.issued_supply,
            timestamp: asset.timestamp,
            added_at: asset.added_at,
            balance: map_asset_balance(asset.balance),
            media: asset.media.map(map_media),
        })
    }

    pub fn issueassetuda(&self, request: SdkIssueAssetUdaRequest) -> Result<AssetUda, RlnError> {
        let state = self.handle.app_state();
        let asset = block_on_sdk(sdk::issue_asset_uda(
            state,
            sdk::IssueAssetUdaRequestData {
                ticker: request.ticker,
                name: request.name,
                details: request.details,
                precision: request.precision,
                media_file_digest: request.media_file_digest,
                attachments_file_digests: request.attachments_file_digests,
            },
        ))?;

        Ok(AssetUda {
            asset_id: ContractId::from_str(&asset.asset_id).map_err(|_| RlnError::Internal)?,
            ticker: asset.ticker,
            name: asset.name,
            details: asset.details,
            precision: asset.precision,
            timestamp: asset.timestamp,
            added_at: asset.added_at,
            balance: map_asset_balance(asset.balance),
            token: asset.token.map(|t| TokenLight {
                index: t.index,
                ticker: t.ticker,
                name: t.name,
                details: t.details,
                embedded_media: t.embedded_media,
                media: t.media.map(map_media),
                attachments: t
                    .attachments
                    .into_iter()
                    .map(|(k, v)| MediaAttachment {
                        key: k,
                        media: map_media(v),
                    })
                    .collect(),
                reserves: t.reserves,
            }),
        })
    }

    pub fn postassetmedia(
        &self,
        request: SdkPostAssetMediaRequest,
    ) -> Result<SdkPostAssetMediaResponse, RlnError> {
        let state = self.handle.app_state();
        let response = block_on_sdk(sdk::post_asset_media(state, request.file_bytes))?;
        Ok(SdkPostAssetMediaResponse {
            digest: response.digest,
        })
    }

    pub fn rgbinvoice(
        &self,
        request: SdkRgbInvoiceRequest,
    ) -> Result<SdkRgbInvoiceResponse, RlnError> {
        let state = self.handle.app_state();
        let assignment_kind = request.assignment_kind.map(|kind| match kind {
            AssignmentKind::Fungible => sdk::AssignmentKindData::Fungible,
            AssignmentKind::NonFungible => sdk::AssignmentKindData::NonFungible,
            AssignmentKind::InflationRight => sdk::AssignmentKindData::InflationRight,
            AssignmentKind::ReplaceRight => sdk::AssignmentKindData::ReplaceRight,
            AssignmentKind::Any => sdk::AssignmentKindData::Any,
        });
        let response = block_on_sdk(sdk::rgb_invoice(
            state,
            sdk::RgbInvoiceRequestData {
                asset_id: request.asset_id.map(|id| id.to_string()),
                assignment_kind,
                assignment_amount: request.assignment_amount,
                duration_seconds: request.duration_seconds,
                min_confirmations: request.min_confirmations,
                witness: request.witness,
            },
        ))?;
        Ok(SdkRgbInvoiceResponse {
            recipient_id: RecipientId(response.recipient_id),
            invoice: response.invoice,
            expiration_timestamp: response.expiration_timestamp,
            batch_transfer_idx: response.batch_transfer_idx,
        })
    }

    pub fn keysend(&self, request: SdkKeysendRequest) -> Result<SdkKeysendResponse, RlnError> {
        let state = self.handle.app_state();
        let response = block_on_sdk(sdk::keysend(
            state,
            sdk::KeysendRequestData {
                dest_pubkey: request.dest_pubkey.to_string(),
                amt_msat: request.amt_msat,
                asset_id: request.asset_id.map(|id| id.to_string()),
                asset_amount: request.asset_amount,
            },
        ))?;

        let status = match response.status {
            crate::sdk::HtlcStatus::Pending => HtlcStatus::Pending,
            crate::sdk::HtlcStatus::Succeeded => HtlcStatus::Succeeded,
            crate::sdk::HtlcStatus::Failed => HtlcStatus::Failed,
        };
        let payment_hash =
            <PaymentHash as UniffiCustomTypeConverter>::into_custom(response.payment_hash)
                .map_err(|_| RlnError::Internal)?;
        Ok(SdkKeysendResponse {
            payment_hash,
            payment_preimage: response.payment_preimage,
            status,
        })
    }

    pub fn sendbtc(&self, request: SdkSendBtcRequest) -> Result<SdkSendBtcResponse, RlnError> {
        let state = self.handle.app_state();
        let response = block_on_sdk(sdk::send_btc(
            state,
            sdk::SendBtcRequestData {
                amount: request.amount,
                address: request.address,
                fee_rate: request.fee_rate,
                skip_sync: request.skip_sync,
            },
        ))?;
        let txid = Txid::from_str(&response.txid).map_err(|_| RlnError::Internal)?;
        Ok(SdkSendBtcResponse { txid })
    }

    pub fn makerinit(
        &self,
        request: SdkMakerInitRequest,
    ) -> Result<SdkMakerInitResponse, RlnError> {
        let state = self.handle.app_state();
        let response = block_on_sdk(sdk::maker_init(
            state,
            sdk::MakerInitRequestData {
                qty_from: request.qty_from,
                qty_to: request.qty_to,
                from_asset: request.from_asset.map(|v| v.to_string()),
                to_asset: request.to_asset.map(|v| v.to_string()),
                timeout_sec: request.timeout_sec,
            },
        ))?;
        let payment_hash =
            <PaymentHash as UniffiCustomTypeConverter>::into_custom(response.payment_hash)
                .map_err(|_| RlnError::Internal)?;
        Ok(SdkMakerInitResponse {
            payment_hash,
            payment_secret: response.payment_secret,
            swapstring: response.swapstring,
        })
    }

    pub fn makerexecute(&self, request: SdkMakerExecuteRequest) -> Result<(), RlnError> {
        let state = self.handle.app_state();
        block_on_sdk(sdk::maker_execute(
            state,
            sdk::MakerExecuteRequestData {
                swapstring: request.swapstring,
                payment_secret: request.payment_secret,
                taker_pubkey: request.taker_pubkey.to_string(),
            },
        ))?;
        Ok(())
    }

    pub fn taker(&self, request: SdkTakerRequest) -> Result<(), RlnError> {
        let state = self.handle.app_state();
        block_on_sdk(sdk::taker(
            state,
            sdk::TakerRequestData {
                swapstring: request.swapstring,
            },
        ))?;
        Ok(())
    }

    pub fn sendonionmessage(&self, request: SdkSendOnionMessageRequest) -> Result<(), RlnError> {
        let state = self.handle.app_state();
        block_on_sdk(sdk::send_onion_message(
            state,
            sdk::SendOnionMessageRequestData {
                node_ids: request
                    .node_ids
                    .into_iter()
                    .map(|v| v.to_string())
                    .collect(),
                tlv_type: request.tlv_type,
                data: request.data,
            },
        ))?;
        Ok(())
    }

    pub fn openchannel(
        &self,
        request: SdkOpenChannelRequest,
    ) -> Result<SdkOpenChannelResponse, RlnError> {
        use bitcoin::hex::DisplayHex;
        use bitcoin::hex::FromHex;

        let state = self.handle.app_state();
        let response = block_on_sdk(sdk::open_channel(
            state,
            sdk::OpenChannelRequestData {
                peer_pubkey_and_opt_addr: request.peer_pubkey_and_opt_addr,
                capacity_sat: request.capacity_sat,
                push_msat: request.push_msat,
                asset_amount: request.asset_amount,
                asset_id: request.asset_id.map(|id| id.to_string()),
                public: request.public,
                with_anchors: request.with_anchors,
                fee_base_msat: request.fee_base_msat,
                fee_proportional_millionths: request.fee_proportional_millionths,
                temporary_channel_id: request
                    .temporary_channel_id
                    .map(|id| id.0.as_hex().to_string()),
                push_asset_amount: request.push_asset_amount,
                virtual_open_mode: request.virtual_open_mode,
            },
        ))?;
        let hex = response.temporary_channel_id;
        let bytes = Vec::<u8>::from_hex(&hex).map_err(|_| RlnError::Internal)?;
        if bytes.len() != 32 {
            return Err(RlnError::Internal);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(SdkOpenChannelResponse {
            temporary_channel_id: lightning::ln::types::ChannelId(arr),
        })
    }

    pub fn sendpayment(
        &self,
        request: SdkSendPaymentRequest,
    ) -> Result<SdkSendPaymentResponse, RlnError> {
        let state = self.handle.app_state();
        let response = block_on_sdk(sdk::send_payment(
            state,
            sdk::SendPaymentRequestData {
                invoice: request.invoice,
                amt_msat: request.amt_msat,
                asset_id: request.asset_id.map(|id| id.to_string()),
                asset_amount: request.asset_amount,
            },
        ))?;
        let status = match response.status {
            crate::sdk::HtlcStatus::Pending => HtlcStatus::Pending,
            crate::sdk::HtlcStatus::Succeeded => HtlcStatus::Succeeded,
            crate::sdk::HtlcStatus::Failed => HtlcStatus::Failed,
        };
        let payment_hash = response
            .payment_hash
            .map(|s| {
                <PaymentHash as UniffiCustomTypeConverter>::into_custom(s)
                    .map_err(|_| RlnError::Internal)
            })
            .transpose()?;
        Ok(SdkSendPaymentResponse {
            payment_id: response.payment_id,
            payment_hash,
            payment_secret: response.payment_secret,
            status,
        })
    }

    pub fn refreshtransfers(&self, request: SdkRefreshTransfersRequest) -> Result<(), RlnError> {
        let state = self.handle.app_state();
        block_on_sdk(sdk::refresh_transfers(
            state,
            sdk::RefreshTransfersRequestData {
                skip_sync: request.skip_sync,
            },
        ))?;
        Ok(())
    }

    pub fn failtransfers(
        &self,
        request: SdkFailTransfersRequest,
    ) -> Result<SdkFailTransfersResponse, RlnError> {
        let state = self.handle.app_state();
        let response = block_on_sdk(sdk::fail_transfers(
            state,
            sdk::FailTransfersRequestData {
                batch_transfer_idx: request.batch_transfer_idx,
                no_asset_only: request.no_asset_only,
                skip_sync: request.skip_sync,
            },
        ))?;
        Ok(SdkFailTransfersResponse {
            transfers_changed: response.transfers_changed,
        })
    }

    pub fn sync(&self) -> Result<(), RlnError> {
        let state = self.handle.app_state();
        block_on_sdk(sdk::sync(state))?;
        Ok(())
    }

    pub fn node_info(&self) -> Result<NodeInfo, RlnError> {
        let state = self.handle.app_state();
        let data = block_on_sdk(sdk::node_info(state))?;
        let pubkey = bitcoin::secp256k1::PublicKey::from_str(&data.pubkey)
            .map_err(|_| RlnError::Internal)?;
        Ok(NodeInfo {
            pubkey,
            num_channels: data.num_channels as u64,
            num_usable_channels: data.num_usable_channels as u64,
            local_balance_sat: data.local_balance_sat,
            eventual_close_fees_sat: data.eventual_close_fees_sat,
            pending_outbound_payments_sat: data.pending_outbound_payments_sat,
            num_peers: data.num_peers as u64,
            account_xpub_vanilla: data.account_xpub_vanilla,
            account_xpub_colored: data.account_xpub_colored,
            max_media_upload_size_mb: data.max_media_upload_size_mb,
            rgb_htlc_min_msat: data.rgb_htlc_min_msat,
            rgb_channel_capacity_min_sat: data.rgb_channel_capacity_min_sat,
            channel_capacity_min_sat: data.channel_capacity_min_sat,
            channel_capacity_max_sat: data.channel_capacity_max_sat,
            channel_asset_min_amount: data.channel_asset_min_amount,
            channel_asset_max_amount: data.channel_asset_max_amount,
            network_nodes: data.network_nodes as u64,
            network_channels: data.network_channels as u64,
        })
    }

    pub fn get_channel_id(&self, temporary_channel_id: ChannelId) -> Result<ChannelId, RlnError> {
        use bitcoin::hex::DisplayHex;
        use bitcoin::hex::FromHex;

        let state = self.handle.app_state();
        let data = block_on_sdk(sdk::get_channel_id(
            state,
            temporary_channel_id.0.as_hex().to_string(),
        ))?;
        let bytes = Vec::<u8>::from_hex(&data.channel_id).map_err(|_| RlnError::Internal)?;
        if bytes.len() != 32 {
            return Err(RlnError::Internal);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(lightning::ln::types::ChannelId(arr))
    }

    pub fn get_payment(&self, payment_hash: PaymentHash) -> Result<Payment, RlnError> {
        use bitcoin::hex::DisplayHex;

        let state = self.handle.app_state();
        let data = block_on_sdk(sdk::get_payment(state, payment_hash.0.as_hex().to_string()))?;
        map_payment_data(data)
    }

    pub fn list_payments(&self) -> Result<Vec<Payment>, RlnError> {
        let state = self.handle.app_state();
        let payments = block_on_sdk(sdk::list_payments(state))?;
        payments.into_iter().map(map_payment_data).collect()
    }

    pub fn get_swap(&self, payment_hash: PaymentHash, taker: bool) -> Result<Swap, RlnError> {
        use bitcoin::hex::DisplayHex;

        let state = self.handle.app_state();
        let data = block_on_sdk(sdk::get_swap(
            state,
            payment_hash.0.as_hex().to_string(),
            taker,
        ))?;
        map_swap_data(data)
    }

    pub fn list_swaps(&self) -> Result<SwapList, RlnError> {
        let state = self.handle.app_state();
        let data = block_on_sdk(sdk::list_swaps(state))?;
        let taker = data
            .taker
            .into_iter()
            .map(map_swap_data)
            .collect::<Result<Vec<_>, _>>()?;
        let maker = data
            .maker
            .into_iter()
            .map(map_swap_data)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SwapList { taker, maker })
    }

    pub fn list_channels(&self) -> Result<Vec<Channel>, RlnError> {
        use bitcoin::hex::FromHex;

        let state = self.handle.app_state();
        let channels = block_on_sdk(sdk::list_channels(state))?;
        channels
            .into_iter()
            .map(|c| {
                let channel_id_bytes =
                    Vec::<u8>::from_hex(&c.channel_id).map_err(|_| RlnError::Internal)?;
                if channel_id_bytes.len() != 32 {
                    return Err(RlnError::Internal);
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&channel_id_bytes);
                let channel_id = lightning::ln::types::ChannelId(arr);
                let peer_pubkey =
                    PublicKey::from_str(&c.peer_pubkey).map_err(|_| RlnError::Internal)?;
                let funding_txid = c
                    .funding_txid
                    .map(|txid| Txid::from_str(&txid).map_err(|_| RlnError::Internal))
                    .transpose()?;
                let asset_id = c
                    .asset_id
                    .map(|id| ContractId::from_str(&id).map_err(|_| RlnError::Internal))
                    .transpose()?;
                let status = match c.status {
                    crate::sdk::ChannelStatus::Opening => ChannelStatus::Opening,
                    crate::sdk::ChannelStatus::Opened => ChannelStatus::Opened,
                    crate::sdk::ChannelStatus::Closing => ChannelStatus::Closing,
                };
                Ok(Channel {
                    channel_id,
                    peer_pubkey,
                    status,
                    ready: c.ready,
                    capacity_sat: c.capacity_sat,
                    local_balance_sat: c.local_balance_sat,
                    outbound_balance_msat: c.outbound_balance_msat,
                    inbound_balance_msat: c.inbound_balance_msat,
                    next_outbound_htlc_limit_msat: c.next_outbound_htlc_limit_msat,
                    next_outbound_htlc_minimum_msat: c.next_outbound_htlc_minimum_msat,
                    is_usable: c.is_usable,
                    public: c.public,
                    funding_txid,
                    peer_alias: c.peer_alias,
                    short_channel_id: c.short_channel_id,
                    asset_id,
                    asset_local_amount: c.asset_local_amount,
                    asset_remote_amount: c.asset_remote_amount,
                    virtual_open_mode: c.virtual_open_mode,
                })
            })
            .collect()
    }

    pub fn list_peers(&self) -> Result<Vec<Peer>, RlnError> {
        let state = self.handle.app_state();
        let peers = block_on_sdk(sdk::list_peers(state))?;
        peers
            .into_iter()
            .map(|p| {
                let pubkey = PublicKey::from_str(&p.pubkey).map_err(|_| RlnError::Internal)?;
                Ok(Peer { pubkey })
            })
            .collect()
    }

    pub fn list_transactions(&self, skip_sync: bool) -> Result<Vec<Transaction>, RlnError> {
        let state = self.handle.app_state();
        let txs = block_on_sdk(sdk::list_transactions(state, skip_sync))?;
        txs.into_iter()
            .map(|tx| {
                let txid = Txid::from_str(&tx.txid).map_err(|_| RlnError::Internal)?;
                let transaction_type = match tx.transaction_type {
                    crate::sdk::TransactionType::RgbSend => TransactionType::RgbSend,
                    crate::sdk::TransactionType::Drain => TransactionType::Drain,
                    crate::sdk::TransactionType::CreateUtxos => TransactionType::CreateUtxos,
                    crate::sdk::TransactionType::User => TransactionType::User,
                };
                Ok(Transaction {
                    transaction_type,
                    txid,
                    received: tx.received,
                    sent: tx.sent,
                    fee: tx.fee,
                    confirmation_time: tx.confirmation_time.map(|ct| BlockTime {
                        height: ct.height,
                        timestamp: ct.timestamp,
                    }),
                })
            })
            .collect()
    }

    pub fn network_info(&self) -> Result<NetworkInfo, RlnError> {
        let state = self.handle.app_state();
        let info = block_on_sdk(sdk::network_info(state))?;
        Ok(NetworkInfo {
            network: format!("{:?}", info.network),
            height: info.height,
        })
    }

    pub fn address(&self) -> Result<AddressInfo, RlnError> {
        let state = self.handle.app_state();
        let info = block_on_sdk(sdk::address(state))?;
        Ok(AddressInfo {
            address: info.address,
        })
    }

    pub fn btc_balance(&self, skip_sync: bool) -> Result<BtcBalanceInfo, RlnError> {
        let state = self.handle.app_state();
        let bal = block_on_sdk(sdk::btc_balance(state, skip_sync))?;
        Ok(BtcBalanceInfo {
            vanilla: BtcBalance {
                settled: bal.vanilla.settled,
                future: bal.vanilla.future,
                spendable: bal.vanilla.spendable,
            },
            colored: BtcBalance {
                settled: bal.colored.settled,
                future: bal.colored.future,
                spendable: bal.colored.spendable,
            },
        })
    }

    pub fn sign_message(&self, message: String) -> Result<SignMessageResponse, RlnError> {
        let state = self.handle.app_state();
        let resp = block_on_sdk(sdk::sign_message(state, message))?;
        Ok(SignMessageResponse {
            signed_message: resp.signed_message,
        })
    }

    pub fn estimate_fee(&self, blocks: u16) -> Result<EstimateFeeResponse, RlnError> {
        let state = self.handle.app_state();
        let resp = block_on_sdk(sdk::estimate_fee(state, blocks))?;
        Ok(EstimateFeeResponse {
            fee_rate: resp.fee_rate,
        })
    }

    pub fn check_indexer_url(
        &self,
        indexer_url: String,
    ) -> Result<CheckIndexerUrlResponse, RlnError> {
        let state = self.handle.app_state();
        let resp = block_on_sdk(sdk::check_indexer_url(state, indexer_url))?;
        Ok(CheckIndexerUrlResponse {
            indexer_protocol: format!("{:?}", resp.indexer_protocol),
        })
    }

    pub fn check_proxy_endpoint(&self, proxy_endpoint: String) -> Result<(), RlnError> {
        block_on_sdk(sdk::check_proxy_endpoint(proxy_endpoint))
    }

    pub fn asset_balance(&self, asset_id: ContractId) -> Result<AssetBalanceInfo, RlnError> {
        let state = self.handle.app_state();
        let resp = block_on_sdk(sdk::asset_balance(state, asset_id.to_string()))?;
        Ok(map_asset_balance_data(resp))
    }

    pub fn asset_metadata(&self, asset_id: ContractId) -> Result<AssetMetadataInfo, RlnError> {
        let state = self.handle.app_state();
        let resp = block_on_sdk(sdk::asset_metadata(state, asset_id.to_string()))?;
        Ok(AssetMetadataInfo {
            asset_schema: format!("{:?}", resp.asset_schema),
            initial_supply: resp.initial_supply,
            max_supply: resp.max_supply,
            known_circulating_supply: resp.known_circulating_supply,
            timestamp: resp.timestamp,
            name: resp.name,
            precision: resp.precision,
            ticker: resp.ticker,
            details: resp.details,
            token: resp.token.map(map_token),
        })
    }

    pub fn get_asset_media(&self, digest: String) -> Result<AssetMediaResponse, RlnError> {
        let state = self.handle.app_state();
        let resp = block_on_sdk(sdk::get_asset_media(state, digest))?;
        Ok(AssetMediaResponse {
            bytes_hex: resp.bytes_hex,
        })
    }

    pub fn list_assets(
        &self,
        filter_asset_schemas: Vec<String>,
    ) -> Result<ListAssetsResponse, RlnError> {
        let state = self.handle.app_state();
        let filters = filter_asset_schemas
            .into_iter()
            .map(|s| match s.to_lowercase().as_str() {
                "nia" => Ok(rgb_lib::AssetSchema::Nia),
                "uda" => Ok(rgb_lib::AssetSchema::Uda),
                "cfa" => Ok(rgb_lib::AssetSchema::Cfa),
                _ => Err(RlnError::InvalidRequest),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let resp = block_on_sdk(sdk::list_assets(state, filters))?;
        let nia = resp
            .nia
            .map(|v| {
                v.into_iter()
                    .map(|a| {
                        Ok(AssetNia {
                            asset_id: ContractId::from_str(&a.asset_id)
                                .map_err(|_| RlnError::Internal)?,
                            ticker: a.ticker,
                            name: a.name,
                            details: a.details,
                            precision: a.precision,
                            issued_supply: a.issued_supply,
                            timestamp: a.timestamp,
                            added_at: a.added_at,
                            balance: map_asset_balance(a.balance),
                            media: a.media.map(map_media),
                        })
                    })
                    .collect::<Result<Vec<_>, RlnError>>()
            })
            .transpose()?;
        let uda = resp
            .uda
            .map(|v| {
                v.into_iter()
                    .map(|a| {
                        Ok(AssetUda {
                            asset_id: ContractId::from_str(&a.asset_id)
                                .map_err(|_| RlnError::Internal)?,
                            ticker: a.ticker,
                            name: a.name,
                            details: a.details,
                            precision: a.precision,
                            timestamp: a.timestamp,
                            added_at: a.added_at,
                            balance: map_asset_balance(a.balance),
                            token: a.token.map(|t| TokenLight {
                                index: t.index,
                                ticker: t.ticker,
                                name: t.name,
                                details: t.details,
                                embedded_media: t.embedded_media,
                                media: t.media.map(map_media),
                                attachments: t
                                    .attachments
                                    .into_iter()
                                    .map(|(k, v)| MediaAttachment {
                                        key: k,
                                        media: map_media(v),
                                    })
                                    .collect(),
                                reserves: t.reserves,
                            }),
                        })
                    })
                    .collect::<Result<Vec<_>, RlnError>>()
            })
            .transpose()?;
        let cfa = resp
            .cfa
            .map(|v| {
                v.into_iter()
                    .map(|a| {
                        Ok(AssetCfa {
                            asset_id: ContractId::from_str(&a.asset_id)
                                .map_err(|_| RlnError::Internal)?,
                            name: a.name,
                            details: a.details,
                            precision: a.precision,
                            issued_supply: a.issued_supply,
                            timestamp: a.timestamp,
                            added_at: a.added_at,
                            balance: map_asset_balance(a.balance),
                            media: a.media.map(map_media),
                        })
                    })
                    .collect::<Result<Vec<_>, RlnError>>()
            })
            .transpose()?;
        Ok(ListAssetsResponse { nia, uda, cfa })
    }

    pub fn decode_ln_invoice(
        &self,
        invoice: Bolt11Invoice,
    ) -> Result<DecodeLnInvoiceResponse, RlnError> {
        let state = self.handle.app_state();
        let resp = block_on_sdk(sdk::decode_ln_invoice(state, invoice.to_string()))?;
        let asset_id = resp
            .asset_id
            .map(|id| ContractId::from_str(&id).map_err(|_| RlnError::Internal))
            .transpose()?;
        let payment_hash =
            <PaymentHash as UniffiCustomTypeConverter>::into_custom(resp.payment_hash)
                .map_err(|_| RlnError::Internal)?;
        let payee_pubkey = resp
            .payee_pubkey
            .map(|p| PublicKey::from_str(&p).map_err(|_| RlnError::Internal))
            .transpose()?;
        Ok(DecodeLnInvoiceResponse {
            amt_msat: resp.amt_msat,
            expiry_sec: resp.expiry_sec,
            timestamp: resp.timestamp,
            asset_id,
            asset_amount: resp.asset_amount,
            payment_hash,
            payment_secret: resp.payment_secret,
            payee_pubkey,
            network: format!("{:?}", resp.network),
        })
    }

    pub fn decode_rgb_invoice(
        &self,
        invoice: String,
    ) -> Result<DecodeRgbInvoiceResponse, RlnError> {
        let state = self.handle.app_state();
        let resp = block_on_sdk(sdk::decode_rgb_invoice(state, invoice))?;
        let asset_id = resp
            .asset_id
            .map(|id| ContractId::from_str(&id).map_err(|_| RlnError::Internal))
            .transpose()?;
        Ok(DecodeRgbInvoiceResponse {
            recipient_id: resp.recipient_id,
            recipient_type: format!("{:?}", resp.recipient_type),
            asset_schema: resp.asset_schema.map(|s| format!("{:?}", s)),
            asset_id,
            assignment: format!("{:?}", resp.assignment),
            network: format!("{:?}", resp.network),
            expiration_timestamp: resp.expiration_timestamp,
            transport_endpoints: resp.transport_endpoints,
        })
    }

    pub fn invoice_status(&self, invoice: Bolt11Invoice) -> Result<InvoiceStatus, RlnError> {
        let state = self.handle.app_state();
        let resp = block_on_sdk(sdk::invoice_status(state, invoice.to_string()))?;
        Ok(match resp.status {
            crate::sdk::InvoiceStatus::Pending => InvoiceStatus::Pending,
            crate::sdk::InvoiceStatus::Succeeded => InvoiceStatus::Succeeded,
            crate::sdk::InvoiceStatus::Failed => InvoiceStatus::Failed,
            crate::sdk::InvoiceStatus::Expired => InvoiceStatus::Expired,
        })
    }

    pub fn list_transfers(&self, asset_id: ContractId) -> Result<Vec<Transfer>, RlnError> {
        let state = self.handle.app_state();
        let resp = block_on_sdk(sdk::list_transfers(state, asset_id.to_string()))?;
        resp.into_iter()
            .map(|t| {
                let txid = t
                    .txid
                    .map(|v| Txid::from_str(&v).map_err(|_| RlnError::Internal))
                    .transpose()?;
                Ok(Transfer {
                    idx: t.idx,
                    created_at: t.created_at,
                    updated_at: t.updated_at,
                    status: format!("{:?}", t.status),
                    requested_assignment: t.requested_assignment.map(|a| format!("{:?}", a)),
                    assignments: t
                        .assignments
                        .into_iter()
                        .map(|a| format!("{:?}", a))
                        .collect(),
                    kind: format!("{:?}", t.kind),
                    txid,
                    recipient_id: t.recipient_id,
                    receive_utxo: t.receive_utxo,
                    change_utxo: t.change_utxo,
                    expiration: t.expiration,
                    transport_endpoints: t
                        .transport_endpoints
                        .into_iter()
                        .map(|e| TransferTransportEndpoint {
                            endpoint: e.endpoint,
                            transport_type: format!("{:?}", e.transport_type),
                            used: e.used,
                        })
                        .collect(),
                })
            })
            .collect()
    }

    pub fn list_unspents(&self, skip_sync: bool) -> Result<Vec<Unspent>, RlnError> {
        let state = self.handle.app_state();
        let resp = block_on_sdk(sdk::list_unspents(state, skip_sync))?;
        resp.into_iter()
            .map(|u| {
                Ok(Unspent {
                    utxo: Utxo {
                        outpoint: u.utxo.outpoint,
                        btc_amount: u.utxo.btc_amount,
                        colorable: u.utxo.colorable,
                    },
                    rgb_allocations: u
                        .rgb_allocations
                        .into_iter()
                        .map(|a| {
                            let asset_id = a
                                .asset_id
                                .map(|id| ContractId::from_str(&id).map_err(|_| RlnError::Internal))
                                .transpose()?;
                            Ok(RgbAllocation {
                                asset_id,
                                assignment: format!("{:?}", a.assignment),
                                settled: a.settled,
                            })
                        })
                        .collect::<Result<Vec<_>, RlnError>>()?,
                })
            })
            .collect()
    }

    pub fn ln_invoice(&self, request: LnInvoiceRequest) -> Result<LnInvoiceResponse, RlnError> {
        let state = self.handle.app_state();
        let asset_id = request.asset_id.map(|a| a.to_string());
        let data = block_on_sdk(sdk::create_ln_invoice(
            state,
            request.amt_msat,
            request.expiry_sec,
            asset_id,
            request.asset_amount,
        ))?;
        let invoice = Bolt11Invoice::from_str(&data.invoice).map_err(|_| RlnError::Internal)?;
        Ok(LnInvoiceResponse { invoice })
    }

    pub fn send_rgb(&self, request: SendRgbRequest) -> Result<SendRgbResponse, RlnError> {
        send_rgb_from_state(self.handle.app_state(), request)
    }
}

pub fn sdk_initialize(request: SdkInitRequest) -> Result<(), RlnError> {
    // Compatibility path for existing clients using process-global state.
    let handle = handle_from_request(request)?;
    set_uniffi_node_handle(handle);
    Ok(())
}

pub fn sdk_shutdown() {
    if let Ok(state) = get_uniffi_app_state() {
        let _ = block_on_sdk(async move {
            let handle = NodeHandle::from_app_state(state);
            handle.shutdown().await;
            Ok::<(), crate::error::APIError>(())
        });
    }
    clear_uniffi_node_handle();
}

pub fn sdk_node_info() -> Result<NodeInfo, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.node_info()
}

pub fn sdk_get_channel_id(temporary_channel_id: ChannelId) -> Result<ChannelId, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.get_channel_id(temporary_channel_id)
}

pub fn sdk_get_payment(payment_hash: PaymentHash) -> Result<Payment, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.get_payment(payment_hash)
}

pub fn sdk_list_payments() -> Result<Vec<Payment>, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.list_payments()
}

pub fn sdk_get_swap(payment_hash: PaymentHash, taker: bool) -> Result<Swap, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.get_swap(payment_hash, taker)
}

pub fn sdk_list_swaps() -> Result<SwapList, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.list_swaps()
}

pub fn sdk_list_channels() -> Result<Vec<Channel>, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.list_channels()
}

pub fn sdk_list_peers() -> Result<Vec<Peer>, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.list_peers()
}

pub fn sdk_list_transactions(skip_sync: bool) -> Result<Vec<Transaction>, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.list_transactions(skip_sync)
}

pub fn sdk_network_info() -> Result<NetworkInfo, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.network_info()
}

pub fn sdk_address() -> Result<AddressInfo, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.address()
}

pub fn sdk_btc_balance(skip_sync: bool) -> Result<BtcBalanceInfo, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.btc_balance(skip_sync)
}

pub fn sdk_sign_message(message: String) -> Result<SignMessageResponse, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.sign_message(message)
}

pub fn sdk_estimate_fee(blocks: u16) -> Result<EstimateFeeResponse, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.estimate_fee(blocks)
}

pub fn sdk_check_indexer_url(indexer_url: String) -> Result<CheckIndexerUrlResponse, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.check_indexer_url(indexer_url)
}

pub fn sdk_check_proxy_endpoint(proxy_endpoint: String) -> Result<(), RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.check_proxy_endpoint(proxy_endpoint)
}

pub fn sdk_asset_balance(asset_id: ContractId) -> Result<AssetBalanceInfo, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.asset_balance(asset_id)
}

pub fn sdk_asset_metadata(asset_id: ContractId) -> Result<AssetMetadataInfo, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.asset_metadata(asset_id)
}

pub fn sdk_get_asset_media(digest: String) -> Result<AssetMediaResponse, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.get_asset_media(digest)
}

pub fn sdk_list_assets(filter_asset_schemas: Vec<String>) -> Result<ListAssetsResponse, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.list_assets(filter_asset_schemas)
}

pub fn sdk_decode_ln_invoice(invoice: Bolt11Invoice) -> Result<DecodeLnInvoiceResponse, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.decode_ln_invoice(invoice)
}

pub fn sdk_decode_rgb_invoice(invoice: String) -> Result<DecodeRgbInvoiceResponse, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.decode_rgb_invoice(invoice)
}

pub fn sdk_invoice_status(invoice: Bolt11Invoice) -> Result<InvoiceStatus, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.invoice_status(invoice)
}

pub fn sdk_list_transfers(asset_id: ContractId) -> Result<Vec<Transfer>, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.list_transfers(asset_id)
}

pub fn sdk_list_unspents(skip_sync: bool) -> Result<Vec<Unspent>, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.list_unspents(skip_sync)
}

pub fn sdk_ln_invoice(request: LnInvoiceRequest) -> Result<LnInvoiceResponse, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.ln_invoice(request)
}

pub fn sdk_send_rgb(request: SendRgbRequest) -> Result<SendRgbResponse, RlnError> {
    let handle = NodeHandle::from_app_state(get_uniffi_app_state()?);
    SdkNode { handle }.send_rgb(request)
}

uniffi::include_scaffolding!("rgb_lightning_node");

#[cfg(test)]
mod tests;
