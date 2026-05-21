use super::*;

#[cfg(test)]
mod uniffi_smoke_tests {
    use super::*;
    use crate::disk::FilesystemLogger;
    use crate::utils::{AppState, StaticState};
    use bitcoin::hex::DisplayHex;
    use rgb_lib::BitcoinNetwork;
    use sea_orm::{ConnectOptions, Database};
    use serial_test::serial;
    use std::collections::HashSet;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use tokio::sync::Mutex as TokioMutex;
    use tokio_util::sync::CancellationToken;

    #[test]
    #[serial(uniffi_state)]
    fn uniffi_entrypoints_require_initialized_state() {
        clear_uniffi_app_state();
        assert!(!uniffi_is_initialized());

        let node_info = sdk_node_info();
        assert!(matches!(node_info, Err(RlnError::NotInitialized)));
        let channel_id = sdk_get_channel_id(lightning::ln::types::ChannelId([0u8; 32]));
        assert!(matches!(channel_id, Err(RlnError::NotInitialized)));
        let payment_hash = lightning::types::payment::PaymentHash([0u8; 32]);
        let payment = sdk_get_payment(payment_hash, PaymentType::Outbound);
        assert!(matches!(payment, Err(RlnError::NotInitialized)));
        let swap = sdk_get_swap(lightning::types::payment::PaymentHash([0u8; 32]), true);
        assert!(matches!(swap, Err(RlnError::NotInitialized)));

        let invoice = sdk_ln_invoice(LnInvoiceRequest {
            amt_msat: Some(1000),
            expiry_sec: 3600,
            asset_id: None,
            asset_amount: None,
            payment_hash: None,
            description_hash: None,
        });
        assert!(matches!(invoice, Err(RlnError::NotInitialized)));

        let hodl_hash = lightning::types::payment::PaymentHash([3u8; 32]);
        let cancel_hodl = sdk_cancelhodlinvoice(CancelHodlInvoiceRequest {
            payment_hash: hodl_hash,
        });
        assert!(matches!(cancel_hodl, Err(RlnError::NotInitialized)));

        let claim_hodl = sdk_claimhodlinvoice(ClaimHodlInvoiceRequest {
            payment_hash: hodl_hash,
            payment_preimage: "11".repeat(32),
        });
        assert!(matches!(claim_hodl, Err(RlnError::NotInitialized)));

        let inflate_asset_id =
            ContractId::from_str("rgb:CJkb4YZw-jRiz2sk-~PARPio-wtVYI1c-XAEYCqO-wTfvRZ8").unwrap();
        let inflate = sdk_inflate(InflateRequest {
            asset_id: inflate_asset_id,
            inflation_amounts: vec![1],
            fee_rate: 1,
            min_confirmations: 1,
        });
        assert!(matches!(inflate, Err(RlnError::NotInitialized)));

        let send_rgb = sdk_send_rgb(SendRgbRequest {
            donation: false,
            fee_rate: 1,
            min_confirmations: 1,
            recipient_groups: vec![],
        });
        assert!(matches!(send_rgb, Err(RlnError::NotInitialized)));

        let invalid_recipient =
            <RecipientId as UniffiCustomTypeConverter>::into_custom("not-recipient-id".to_string());
        assert!(invalid_recipient.is_err());
    }

    fn mock_locked_state() -> Arc<AppState> {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("rln_db");
        let connection_string = format!("sqlite:{}?mode=rwc", db_path.display());
        let database =
            crate::runtime::block_on(Database::connect(ConnectOptions::new(connection_string)))
                .expect("mock database connection");
        Arc::new(AppState {
            static_state: Arc::new(StaticState {
                ldk_peer_listening_port: 9735,
                network: BitcoinNetwork::Regtest,
                storage_dir_path: tmp.path().to_path_buf(),
                ldk_data_dir: tmp.path().join(".ldk"),
                logger: Arc::new(FilesystemLogger::new(tmp.path().to_path_buf())),
                max_media_upload_size_mb: 1,
                enable_virtual_channels_v0: false,
                virtual_peer_pubkeys: vec![],
                database: Arc::new(database),
                lsp_base_url: None,
                lsp_bearer_token: None,
                vss_url: None,
                vss_allow_empty_restore: false,
            }),
            cancel_token: CancellationToken::new(),
            unlocked_app_state: Arc::new(TokioMutex::new(None)),
            ldk_background_services: Arc::new(Mutex::new(None)),
            changing_state: Mutex::new(false),
            root_public_key: None,
            revoked_tokens: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    #[test]
    #[serial(uniffi_state)]
    fn uniffi_entrypoints_use_registered_state() {
        set_uniffi_app_state(mock_locked_state());
        assert!(uniffi_is_initialized());
        let node_info = sdk_node_info();
        assert!(matches!(node_info, Err(RlnError::NotInitialized)));
        let channel_id = sdk_get_channel_id(lightning::ln::types::ChannelId([0u8; 32]));
        assert!(matches!(channel_id, Err(RlnError::NotInitialized)));
        let hodl_hash = lightning::types::payment::PaymentHash([4u8; 32]);
        let cancel_hodl = sdk_cancelhodlinvoice(CancelHodlInvoiceRequest {
            payment_hash: hodl_hash,
        });
        assert!(matches!(cancel_hodl, Err(RlnError::NotInitialized)));
        let claim_hodl = sdk_claimhodlinvoice(ClaimHodlInvoiceRequest {
            payment_hash: hodl_hash,
            payment_preimage: "22".repeat(32),
        });
        assert!(matches!(claim_hodl, Err(RlnError::NotInitialized)));

        let send_rgb = sdk_send_rgb(SendRgbRequest {
            donation: false,
            fee_rate: 1,
            min_confirmations: 1,
            recipient_groups: vec![],
        });
        assert!(matches!(send_rgb, Err(RlnError::InvalidRequest)));
        clear_uniffi_app_state();
        assert!(!uniffi_is_initialized());
    }

    #[test]
    #[serial(uniffi_state)]
    fn uniffi_instance_entrypoints_work_without_global_registration() {
        clear_uniffi_app_state();
        assert!(!uniffi_is_initialized());

        let node = SdkNode {
            handle: crate::NodeHandle::from_app_state(mock_locked_state()),
        };
        let node_info = node.node_info();
        assert!(matches!(node_info, Err(RlnError::NotInitialized)));
        let hodl_hash = lightning::types::payment::PaymentHash([5u8; 32]);
        let cancel_hodl = node.cancelhodlinvoice(CancelHodlInvoiceRequest {
            payment_hash: hodl_hash,
        });
        assert!(matches!(cancel_hodl, Err(RlnError::NotInitialized)));
        let claim_hodl = node.claimhodlinvoice(ClaimHodlInvoiceRequest {
            payment_hash: hodl_hash,
            payment_preimage: "33".repeat(32),
        });
        assert!(matches!(claim_hodl, Err(RlnError::NotInitialized)));

        let send_rgb = node.send_rgb(SendRgbRequest {
            donation: false,
            fee_rate: 1,
            min_confirmations: 1,
            recipient_groups: vec![],
        });
        assert!(matches!(send_rgb, Err(RlnError::InvalidRequest)));

        // Keep global slot untouched for compatibility wrappers.
        assert!(!uniffi_is_initialized());
    }

    #[test]
    fn uniffi_custom_types_roundtrip_and_reject_invalid_values() {
        let public_key = bitcoin::secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let public_key_builtin = <PublicKey as UniffiCustomTypeConverter>::from_custom(public_key);
        let public_key_roundtrip =
            <PublicKey as UniffiCustomTypeConverter>::into_custom(public_key_builtin).unwrap();
        assert_eq!(public_key_roundtrip, public_key);

        let txid =
            Txid::from_str("4d3f1f0f87f63a01d4fce1ab4cf8fe0cf5e8f7ff7f6ba6748b6ff1571318dd43")
                .unwrap();
        let txid_builtin = <Txid as UniffiCustomTypeConverter>::from_custom(txid);
        let txid_roundtrip =
            <Txid as UniffiCustomTypeConverter>::into_custom(txid_builtin).unwrap();
        assert_eq!(txid_roundtrip, txid);

        let payment_hash = lightning::types::payment::PaymentHash([2u8; 32]);
        let payment_hash_builtin =
            <PaymentHash as UniffiCustomTypeConverter>::from_custom(payment_hash);
        assert_eq!(payment_hash_builtin, [2u8; 32].as_hex().to_string());
        let payment_hash_roundtrip =
            <PaymentHash as UniffiCustomTypeConverter>::into_custom(payment_hash_builtin).unwrap();
        assert_eq!(payment_hash_roundtrip.0, [2u8; 32]);

        let channel_id = lightning::ln::types::ChannelId([1u8; 32]);
        let channel_id_builtin = <ChannelId as UniffiCustomTypeConverter>::from_custom(channel_id);
        assert_eq!(channel_id_builtin, [1u8; 32].as_hex().to_string());
        let channel_id_roundtrip =
            <ChannelId as UniffiCustomTypeConverter>::into_custom(channel_id_builtin).unwrap();
        assert_eq!(channel_id_roundtrip.0, [1u8; 32]);

        assert!(
            <ChannelId as UniffiCustomTypeConverter>::into_custom("deadbeef".to_string()).is_err()
        );
        assert!(
            <PaymentHash as UniffiCustomTypeConverter>::into_custom("deadbeef".to_string())
                .is_err()
        );
        assert!(<ContractId as UniffiCustomTypeConverter>::into_custom(
            "not-a-contract-id".to_string()
        )
        .is_err());
        assert!(<Bolt11Invoice as UniffiCustomTypeConverter>::into_custom(
            "not-an-invoice".to_string()
        )
        .is_err());
        assert!(
            <TransportEndpoint as UniffiCustomTypeConverter>::into_custom(
                "not-a-transport-endpoint".to_string()
            )
            .is_err()
        );
        let endpoint = <TransportEndpoint as UniffiCustomTypeConverter>::into_custom(
            "rpc://127.0.0.1:3000/json-rpc".to_string(),
        )
        .unwrap();
        assert_eq!(
            <TransportEndpoint as UniffiCustomTypeConverter>::from_custom(endpoint),
            "rpc://127.0.0.1:3000/json-rpc".to_string()
        );
    }

    #[test]
    fn uniffi_error_mapping_is_stable_for_core_api_errors() {
        assert!(matches!(
            super::super::state::map_api_error(crate::error::APIError::LockedNode),
            RlnError::NotInitialized
        ));
        assert!(matches!(
            super::super::state::map_api_error(crate::error::APIError::PaymentNotFound(
                "x".to_string()
            )),
            RlnError::NotFound
        ));
        assert!(matches!(
            super::super::state::map_api_error(crate::error::APIError::SwapNotFound(
                "x".to_string()
            )),
            RlnError::NotFound
        ));
        assert!(matches!(
            super::super::state::map_api_error(crate::error::APIError::OpenChannelInProgress),
            RlnError::Conflict
        ));
        assert!(matches!(
            super::super::state::map_api_error(crate::error::APIError::IO(std::io::Error::other(
                "invalid"
            ))),
            RlnError::Internal
        ));
        assert!(matches!(
            super::super::state::map_api_error(crate::error::APIError::InvalidPeerInfo(
                "invalid peer".to_string()
            )),
            RlnError::InvalidRequest
        ));
        assert!(matches!(
            super::super::state::map_api_error(crate::error::APIError::NoAvailableUtxos),
            RlnError::Conflict
        ));
        assert!(matches!(
            super::super::state::map_api_error(crate::error::APIError::NoValidTransportEndpoint),
            RlnError::Conflict
        ));
        assert!(matches!(
            super::super::state::map_api_error(crate::error::APIError::WrongPassword),
            RlnError::InvalidRequest
        ));
    }

    #[test]
    fn map_payment_data_preserves_preimage() {
        let payment_hash_hex = [7u8; 32].as_hex().to_string();
        let expected_preimage = Some("11".repeat(32));
        let data = crate::sdk::PaymentData {
            amt_msat: Some(1000),
            asset_amount: None,
            asset_id: None,
            payment_hash: payment_hash_hex.clone(),
            payment_type: crate::sdk::PaymentType::InboundHodl,
            status: crate::sdk::HtlcStatus::Succeeded,
            created_at: 1,
            updated_at: 2,
            payee_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            preimage: expected_preimage.clone(),
        };

        let mapped = map_payment_data(data).expect("payment mapping should succeed");
        assert_eq!(mapped.payment_hash.0, [7u8; 32]);
        assert_eq!(mapped.preimage, expected_preimage);
        assert!(matches!(mapped.payment_type, PaymentType::InboundHodl));
    }
}
