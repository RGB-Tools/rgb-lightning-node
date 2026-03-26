#[cfg(feature = "uniffi")]
use bitcoin::hex::DisplayHex;
#[cfg(feature = "uniffi")]
use bitcoin::hex::FromHex;
#[cfg(feature = "uniffi")]
use std::str::FromStr;

#[cfg(feature = "uniffi")]
use crate::UniffiCustomTypeConverter;

#[cfg(feature = "uniffi")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniffiBindingState {
    Ready,
}

#[cfg(feature = "uniffi")]
impl UniffiCustomTypeConverter for bitcoin::secp256k1::PublicKey {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        bitcoin::secp256k1::PublicKey::from_str(&val)
            .map_err(|_| crate::RlnError::InvalidRequest.into())
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.to_string()
    }
}

#[cfg(feature = "uniffi")]
impl UniffiCustomTypeConverter for bitcoin::Txid {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        bitcoin::Txid::from_str(&val).map_err(|_| crate::RlnError::InvalidRequest.into())
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.to_string()
    }
}

#[cfg(feature = "uniffi")]
impl UniffiCustomTypeConverter for rgb_lib::ContractId {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        rgb_lib::ContractId::from_str(&val).map_err(|_| crate::RlnError::InvalidRequest.into())
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.to_string()
    }
}

#[cfg(feature = "uniffi")]
impl UniffiCustomTypeConverter for lightning::ln::types::ChannelId {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        let bytes = Vec::<u8>::from_hex(&val).map_err(|_| crate::RlnError::InvalidRequest)?;
        if bytes.len() != 32 {
            return Err(crate::RlnError::InvalidRequest.into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(lightning::ln::types::ChannelId(arr))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0.as_hex().to_string()
    }
}

#[cfg(feature = "uniffi")]
impl UniffiCustomTypeConverter for lightning::types::payment::PaymentHash {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        let bytes = Vec::<u8>::from_hex(&val).map_err(|_| crate::RlnError::InvalidRequest)?;
        if bytes.len() != 32 {
            return Err(crate::RlnError::InvalidRequest.into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(lightning::types::payment::PaymentHash(arr))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0.as_hex().to_string()
    }
}

#[cfg(feature = "uniffi")]
impl UniffiCustomTypeConverter for crate::RecipientId {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        rgb_lib::wallet::RecipientInfo::new(val.clone())
            .map_err(|_| crate::RlnError::InvalidRequest)?;
        Ok(crate::RecipientId(val))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0
    }
}

#[cfg(feature = "uniffi")]
impl UniffiCustomTypeConverter for lightning_invoice::Bolt11Invoice {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        lightning_invoice::Bolt11Invoice::from_str(&val)
            .map_err(|_| crate::RlnError::InvalidRequest.into())
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.to_string()
    }
}

#[cfg(feature = "uniffi")]
impl UniffiCustomTypeConverter for crate::TransportEndpoint {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        rgb_lib::RgbTransport::from_str(&val).map_err(|_| crate::RlnError::InvalidRequest)?;
        Ok(crate::TransportEndpoint(val))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0
    }
}
