use serial_test::serial;
use std::str::FromStr;

use rgb_lightning_node::test_utils::{
    clear_uniffi_state_for_tests, error_mapping_snapshot_for_tests, mock_locked_app_state,
    node_handle_from_mock_state_for_tests, register_uniffi_state_for_tests,
};
use rgb_lightning_node::{
    sdk_get_channel_id, sdk_get_payment, sdk_get_swap, sdk_ln_invoice, sdk_node_info, sdk_send_rgb,
    uniffi_is_initialized, Bolt11Invoice, ChannelId, ContractId, LnInvoiceRequest, PaymentHash,
    PublicKey, RecipientId, RlnError, SendRgbRequest, TransportEndpoint, Txid,
    UniffiCustomTypeConverter,
};

#[test]
#[serial(uniffi_state)]
fn uniffi_entrypoints_require_initialized_state() {
    clear_uniffi_state_for_tests();

    assert!(!uniffi_is_initialized());
    assert!(matches!(sdk_node_info(), Err(RlnError::NotInitialized)));
    assert!(matches!(
        sdk_get_channel_id(lightning::ln::types::ChannelId([0u8; 32])),
        Err(RlnError::NotInitialized)
    ));
    assert!(matches!(
        sdk_get_payment(lightning::types::payment::PaymentHash([0u8; 32])),
        Err(RlnError::NotInitialized)
    ));
    assert!(matches!(
        sdk_get_swap(lightning::types::payment::PaymentHash([0u8; 32]), true),
        Err(RlnError::NotInitialized)
    ));
}

#[test]
#[serial(uniffi_state)]
fn register_and_clear_uniffi_state_transitions() {
    let state = mock_locked_app_state();
    register_uniffi_state_for_tests(&state);

    assert!(uniffi_is_initialized());
    assert!(matches!(sdk_node_info(), Err(RlnError::NotInitialized)));

    clear_uniffi_state_for_tests();
    assert!(!uniffi_is_initialized());
}

#[test]
#[serial(uniffi_state)]
fn locked_state_does_not_bypass_unlock_guards() {
    let state = mock_locked_app_state();
    register_uniffi_state_for_tests(&state);

    let invoice = sdk_ln_invoice(LnInvoiceRequest {
        amt_msat: Some(1000),
        expiry_sec: 3600,
        asset_id: None,
        asset_amount: None,
    });
    assert!(matches!(invoice, Err(RlnError::NotInitialized)));

    let send_rgb = sdk_send_rgb(SendRgbRequest {
        donation: false,
        fee_rate: 1,
        min_confirmations: 1,
        skip_sync: true,
        recipient_groups: vec![],
    });
    assert!(matches!(send_rgb, Err(RlnError::InvalidRequest)));

    clear_uniffi_state_for_tests();
}

#[test]
fn custom_types_roundtrip() {
    let public_key =
        PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
    let built_in = <PublicKey as UniffiCustomTypeConverter>::from_custom(public_key);
    let roundtrip = <PublicKey as UniffiCustomTypeConverter>::into_custom(built_in).unwrap();
    assert_eq!(roundtrip, public_key);

    let txid =
        Txid::from_str("4d3f1f0f87f63a01d4fce1ab4cf8fe0cf5e8f7ff7f6ba6748b6ff1571318dd43").unwrap();
    let built_in = <Txid as UniffiCustomTypeConverter>::from_custom(txid);
    let roundtrip = <Txid as UniffiCustomTypeConverter>::into_custom(built_in).unwrap();
    assert_eq!(roundtrip, txid);

    let channel_id = lightning::ln::types::ChannelId([1u8; 32]);
    let built_in = <ChannelId as UniffiCustomTypeConverter>::from_custom(channel_id);
    let roundtrip = <ChannelId as UniffiCustomTypeConverter>::into_custom(built_in).unwrap();
    assert_eq!(roundtrip.0, [1u8; 32]);

    let payment_hash = lightning::types::payment::PaymentHash([2u8; 32]);
    let built_in = <PaymentHash as UniffiCustomTypeConverter>::from_custom(payment_hash);
    let roundtrip = <PaymentHash as UniffiCustomTypeConverter>::into_custom(built_in).unwrap();
    assert_eq!(roundtrip.0, [2u8; 32]);
}

#[test]
fn custom_types_reject_invalid_values() {
    assert!(<ChannelId as UniffiCustomTypeConverter>::into_custom("deadbeef".to_string()).is_err());
    assert!(
        <PaymentHash as UniffiCustomTypeConverter>::into_custom("deadbeef".to_string()).is_err()
    );
    assert!(<ContractId as UniffiCustomTypeConverter>::into_custom(
        "not-a-contract-id".to_string()
    )
    .is_err());
    assert!(<Bolt11Invoice as UniffiCustomTypeConverter>::into_custom(
        "not-an-invoice".to_string()
    )
    .is_err());
    assert!(<RecipientId as UniffiCustomTypeConverter>::into_custom(
        "not-recipient-id".to_string()
    )
    .is_err());
    assert!(
        <TransportEndpoint as UniffiCustomTypeConverter>::into_custom(
            "not-a-transport-endpoint".to_string()
        )
        .is_err()
    );
}

#[test]
fn api_error_mapping_remains_stable() {
    let snapshot = error_mapping_snapshot_for_tests();

    assert!(matches!(snapshot.locked_node, RlnError::NotInitialized));
    assert!(matches!(snapshot.payment_not_found, RlnError::NotFound));
    assert!(matches!(snapshot.io_error, RlnError::Internal));
}

#[test]
#[serial(uniffi_state)]
fn node_handle_register_unregister_controls_uniffi_state() {
    clear_uniffi_state_for_tests();

    let state = mock_locked_app_state();
    let handle = node_handle_from_mock_state_for_tests(&state);

    handle.register_for_uniffi();
    assert!(uniffi_is_initialized());

    handle.unregister_for_uniffi();
    assert!(!uniffi_is_initialized());
}

#[test]
#[serial(uniffi_state)]
fn repeated_register_unregister_is_stable() {
    clear_uniffi_state_for_tests();

    let state = mock_locked_app_state();
    let handle = node_handle_from_mock_state_for_tests(&state);

    handle.register_for_uniffi();
    handle.register_for_uniffi();
    assert!(uniffi_is_initialized());

    handle.unregister_for_uniffi();
    handle.unregister_for_uniffi();
    assert!(!uniffi_is_initialized());
}
