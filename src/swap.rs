use lightning::{impl_writeable_tlv_based, ln::PaymentHash};
use rgbstd::contract::ContractId;
use std::convert::TryInto;
use std::str::FromStr;

use crate::utils::hex_str_to_vec;

#[derive(Debug, Clone)]
pub struct Swap {
    pub(crate) qty_from: u64,
    pub(crate) qty_to: u64,
    pub(crate) from_asset: Option<ContractId>,
    pub(crate) to_asset: Option<ContractId>,
}

impl_writeable_tlv_based!(Swap, {
    (0, qty_from, required),
    (1, qty_to, required),
    (2, from_asset, required),
    (3, to_asset, required),
});

impl Swap {
    pub fn same_asset(&self) -> bool {
        self.from_asset == self.to_asset
    }

    pub fn is_from_btc(&self) -> bool {
        self.from_asset.is_none()
    }
    pub fn is_to_btc(&self) -> bool {
        self.to_asset.is_none()
    }

    pub fn is_asset_asset(&self) -> bool {
        !self.is_from_btc() && !self.is_to_btc()
    }
}

#[derive(Debug)]
pub struct SwapString {
    pub swap: Swap,
    pub expiry: u64,
    pub payment_hash: PaymentHash,
}

impl FromStr for SwapString {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.split('/');
        let qty_from = iter.next();
        let from_asset = iter.next();
        let qty_to = iter.next();
        let to_asset = iter.next();
        let expiry = iter.next();
        let payment_hash = iter.next();

        if payment_hash.is_none() || iter.next().is_some() {
            return Err("Wrong number of parts");
        }

        let parse_swapstring_asset = |asset: &str| {
            if asset == "btc" {
                Ok(None)
            } else {
                ContractId::from_str(asset).map(Option::Some)
            }
        };

        let qty_from = qty_from.unwrap().parse::<u64>();
        let qty_to = qty_to.unwrap().parse::<u64>();
        let from_asset = parse_swapstring_asset(from_asset.unwrap());
        let to_asset = parse_swapstring_asset(to_asset.unwrap());
        let expiry = expiry.unwrap().parse::<u64>();
        let payment_hash = hex_str_to_vec(payment_hash.unwrap())
            .and_then(|vec| vec.try_into().ok())
            .map(PaymentHash);

        if qty_from.is_err()
            || from_asset.is_err()
            || qty_to.is_err()
            || to_asset.is_err()
            || expiry.is_err()
            || payment_hash.is_none()
        {
            return Err("Unable to parse");
        }

        let qty_from = qty_from.unwrap();
        let qty_to = qty_to.unwrap();
        let from_asset = from_asset.unwrap();
        let to_asset = to_asset.unwrap();
        let expiry = expiry.unwrap();
        let payment_hash = payment_hash.unwrap();

        if qty_from == 0 || qty_to == 0 || expiry == 0 {
            return Err("qty_from, qty_to and expiry should be positive");
        }

        let swap = Swap {
            qty_from,
            qty_to,
            from_asset,
            to_asset,
        };

        if swap.same_asset() {
            return Err("From and to assets should be different");
        }

        Ok(SwapString {
            swap,
            expiry,
            payment_hash,
        })
    }
}
