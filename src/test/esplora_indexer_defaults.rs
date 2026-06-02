use std::collections::HashMap;

use lightning::chain::chaininterface::ConfirmationTarget;

use crate::indexer::{default_fee_buckets, estimate_fee_rate_sat_per_kw, interpolate_fee_rate};

#[test]
fn default_fee_buckets_populates_all_targets() {
    let buckets = default_fee_buckets();
    for target in [
        ConfirmationTarget::MaximumFeeEstimate,
        ConfirmationTarget::UrgentOnChainSweep,
        ConfirmationTarget::MinAllowedAnchorChannelRemoteFee,
        ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
        ConfirmationTarget::AnchorChannelFee,
        ConfirmationTarget::NonAnchorChannelFee,
        ConfirmationTarget::ChannelCloseMinimum,
        ConfirmationTarget::OutputSpendingFee,
    ] {
        assert!(
            buckets.contains_key(&target),
            "missing default for {target:?}"
        );
    }
}

#[test]
fn interpolation_handles_exact_match() {
    let mut m = HashMap::new();
    m.insert(6u16, 12.0);
    assert_eq!(interpolate_fee_rate(&m, 6), Some(12.0));
}

#[test]
fn interpolation_linearly_interpolates_between_buckets() {
    let mut m = HashMap::new();
    m.insert(2u16, 100.0);
    m.insert(10u16, 20.0);
    let v = interpolate_fee_rate(&m, 6).unwrap();
    assert!((v - 60.0).abs() < 0.001, "got {v}");
}

#[test]
fn interpolation_falls_back_to_default_when_empty() {
    let m: HashMap<u16, f64> = HashMap::new();
    assert_eq!(estimate_fee_rate_sat_per_kw(&m, 6, 5000), 5000);
}
