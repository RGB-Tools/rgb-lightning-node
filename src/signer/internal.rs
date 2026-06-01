use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, Secp256k1};
use lightning::sign::InMemorySigner;
use lightning::sign::KeysManager;
use lightning::sign::SpendableOutputDescriptor;

use super::{RlnChannelSigner, RlnKeysInterface, RlnSignerError};

impl RlnKeysInterface for KeysManager {
    fn sign_spendable_outputs_psbt(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        psbt: Psbt,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Psbt, ()> {
        self.sign_spendable_outputs_psbt(descriptors, psbt, secp_ctx)
    }

    fn sign_rgb_psbt(
        &self,
        _descriptors: Vec<String>,
        _psbt: String,
    ) -> Result<String, RlnSignerError> {
        Err(RlnSignerError::Unsupported(
            "RGB PSBT signing is not implemented via internal signer abstraction yet".to_string(),
        ))
    }
}

impl RlnChannelSigner for InMemorySigner {}
