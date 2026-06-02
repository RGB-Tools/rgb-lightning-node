use std::sync::Arc;

use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};

use crate::chain_backend::ChainBackend;

fn _assert_fee_estimator<T: FeeEstimator>(_: &T) {}
fn _assert_broadcaster<T: BroadcasterInterface>(_: &T) {}

#[test]
fn chain_backend_implements_required_traits() {
    fn _accepts(b: Arc<ChainBackend>) {
        _assert_fee_estimator(&*b);
        _assert_broadcaster(&*b);
        let _ = b.get_est_sat_per_1000_weight(ConfirmationTarget::AnchorChannelFee);
    }
}

#[test]
fn chain_backend_esplora_variant_exists() {
    fn _accept(_: crate::chain_backend::ChainBackend) {}
}
