//! In-process VLS signer exposed over UniFFI (`NativeExternalSigner`).
//!
//! Holder commitment validation uses `commitment_unsigned_tx_hex` when the built commitment tx is
//! RGB-colored (`ExternalChannelSigner::validate_holder_commitment_with_backend`). Counterparty
//! commitment signing uses the VLS summary RPC (`SignRemoteCommitmentTx2`) like vanilla channels;
//! the wire transaction may differ on RGB outputs while balances match the negotiated commitment.
use super::{ExternalSignerHost, RlnError, SdkExternalSignerBootstrap};
use crate::signer::proto::{decode_signer_request, encode_signer_response};
use anyhow::Context;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use rand::rngs::OsRng;
use rand::RngCore;
use signer_external::contract::{
    BootstrapData, ChannelOp, ChannelRequest, ChannelResponse, ExternalSignerBackend,
    SignerRequest, SignerResponse,
};
use signer_external::vls_adapter::vls_real::RealVlsClient;
use signer_external::vls_adapter::VlsSignerAdapter;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use vls_protocol::msgs;
use vls_protocol_client::{Error as VlsClientError, Transport};
use vls_protocol_signer::approver::WarningPositiveApprover;
use vls_protocol_signer::handler::{Handler, InitHandler, RootHandler};
use vls_protocol_signer::lightning_signer;
use vls_protocol_signer::lightning_signer::lightning::sign::ChannelSigner as _;
use vls_protocol_signer::lightning_signer::node::NodeServices;
use vls_protocol_signer::lightning_signer::persist::{DummyPersister, Persist};
use vls_protocol_signer::lightning_signer::policy::filter::PolicyFilter;
use vls_protocol_signer::lightning_signer::policy::simple_validator::{
    make_default_simple_policy, SimpleValidatorFactory,
};
use vls_protocol_signer::lightning_signer::signer::derive::KeyDerivationStyle;
use vls_protocol_signer::lightning_signer::signer::ClockStartingTimeFactory;
use vls_protocol_signer::lightning_signer::util::clock::StandardClock;

struct VlsTransportState {
    init_handler: Option<InitHandler>,
    root_handler: Option<RootHandler>,
    channel_handlers: HashMap<(u64, [u8; 33]), vls_protocol_signer::handler::ChannelHandler>,
    cached_hsmd_init2_reply: Option<Vec<u8>>,
}

struct InProcessVlsTransport {
    state: Mutex<VlsTransportState>,
}

impl InProcessVlsTransport {
    fn new(network: Network, seed: [u8; 32], permissive_policy: bool) -> anyhow::Result<Self> {
        let persister: Arc<dyn Persist> = Arc::new(DummyPersister {});
        let validator_factory: Arc<dyn lightning_signer::policy::validator::ValidatorFactory> =
            if permissive_policy {
                let mut policy = make_default_simple_policy(network);
                policy.filter = PolicyFilter::new_permissive();
                Arc::new(SimpleValidatorFactory::new_with_policy(policy))
            } else {
                Arc::new(SimpleValidatorFactory::new())
            };
        let services = NodeServices {
            validator_factory,
            starting_time_factory: ClockStartingTimeFactory::new(),
            persister,
            clock: Arc::new(StandardClock()),
            trusted_oracle_pubkeys: vec![],
        };

        let config = lightning_signer::node::NodeConfig {
            network,
            key_derivation_style: KeyDerivationStyle::Ldk,
            // In-process native signer is a dev/test helper. Checkpoint validation in vls-core
            // can panic on missing checkpoint state in some environments; keep it off here to
            // avoid taking down the host process during E2E flows.
            use_checkpoints: false,
            allow_deep_reorgs: true,
        };
        let node = Arc::new(lightning_signer::node::Node::new(
            config,
            &seed,
            vec![],
            services,
        ));
        let approver: Arc<dyn vls_protocol_signer::approver::Approve> = if permissive_policy {
            Arc::new(WarningPositiveApprover())
        } else {
            Arc::new(vls_protocol_signer::approver::NegativeApprover())
        };
        let handler = InitHandler::new(1, node, approver, msgs::DEFAULT_MAX_PROTOCOL_VERSION);
        Ok(Self {
            state: Mutex::new(VlsTransportState {
                init_handler: Some(handler),
                root_handler: None,
                channel_handlers: HashMap::new(),
                cached_hsmd_init2_reply: None,
            }),
        })
    }

    fn synthesize_stub_commitment_point(&self, dbid: u64, idx: u64) -> Result<String, RlnError> {
        let state = self.state.lock().map_err(|_| RlnError::Internal)?;
        let root = state.root_handler.as_ref().ok_or(RlnError::Internal)?;
        let node = root.node();
        let chaninfo = node.chaninfo();
        let slot = chaninfo
            .into_iter()
            .find(|slot| slot.oid == dbid)
            .ok_or(RlnError::Internal)?;
        let slot_arc = node.get_channel(&slot.id).map_err(|_| RlnError::Internal)?;
        let slot_guard = slot_arc.lock().map_err(|_| RlnError::Internal)?;
        let point = match &*slot_guard {
            lightning_signer::channel::ChannelSlot::Stub(stub) => stub
                .keys
                .get_per_commitment_point(idx, &Secp256k1::new())
                .map_err(|_| RlnError::Internal)?,
            lightning_signer::channel::ChannelSlot::Ready(chan) => chan
                .keys
                .get_per_commitment_point(idx, &Secp256k1::new())
                .map_err(|_| RlnError::Internal)?,
        };
        Ok(point.serialize().to_lower_hex_string())
    }
}

impl Transport for InProcessVlsTransport {
    fn node_call(&self, message: Vec<u8>) -> Result<Vec<u8>, VlsClientError> {
        let msg_name = msgs::message_name_from_vec(&message);
        let msg = msgs::from_vec(message).map_err(VlsClientError::Protocol)?;
        let mut state = self.state.lock().map_err(|_| VlsClientError::Transport)?;

        if state.root_handler.is_none() {
            let init = state
                .init_handler
                .as_mut()
                .ok_or(VlsClientError::Transport)?;
            let (done, reply_opt) = init.handle(msg).map_err(|e| {
                tracing::debug!(error = ?e, "native signer init handler error");
                VlsClientError::Transport
            })?;
            let reply = reply_opt.ok_or(VlsClientError::Transport)?;
            let reply_vec = reply.as_vec();
            if msg_name == "HsmdInit2" {
                state.cached_hsmd_init2_reply = Some(reply_vec.clone());
            }
            if done {
                let init_taken = state.init_handler.take().ok_or(VlsClientError::Transport)?;
                state.root_handler = Some(init_taken.into());
            }
            return Ok(reply_vec);
        }

        if msg_name == "HsmdInit2" {
            return state
                .cached_hsmd_init2_reply
                .clone()
                .ok_or(VlsClientError::Transport);
        }

        let root = state
            .root_handler
            .as_ref()
            .cloned()
            .ok_or(VlsClientError::Transport)?;
        let reply = root.handle(msg).map_err(|e| {
            tracing::debug!(error = ?e, "native signer root handler error");
            VlsClientError::Transport
        })?;
        Ok(reply.as_vec())
    }

    fn call(
        &self,
        dbid: u64,
        peer_id: vls_protocol::model::PubKey,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, VlsClientError> {
        let msg_name = msgs::message_name_from_vec(&message);
        let msg = msgs::from_vec(message).map_err(VlsClientError::Protocol)?;
        let mut state = self.state.lock().map_err(|_| VlsClientError::Transport)?;
        let root = state
            .root_handler
            .as_ref()
            .cloned()
            .ok_or(VlsClientError::Transport)?;

        if matches!(msg_name.as_str(), "NewChannel" | "GetChannelBasepoints") {
            let reply = root.handle(msg).map_err(|e| {
                tracing::debug!(error = ?e, "native signer root handler error");
                VlsClientError::Transport
            })?;
            return Ok(reply.as_vec());
        }

        let key = (dbid, peer_id.0);
        let handler = state
            .channel_handlers
            .entry(key)
            .or_insert_with(|| root.for_new_client(1, peer_id, dbid));
        let reply = handler.handle(msg).map_err(|e| {
            tracing::debug!(error = ?e, "native signer channel handler error");
            VlsClientError::Transport
        })?;
        Ok(reply.as_vec())
    }
}

#[derive(uniffi::Object)]
pub struct NativeExternalSigner {
    backend: Arc<dyn ExternalSignerBackend>,
    transport: Arc<InProcessVlsTransport>,
}

impl NativeExternalSigner {
    fn parse_network(network: &str) -> Result<Network, RlnError> {
        match network.to_lowercase().as_str() {
            "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
            "testnet" | "testnet4" => Ok(Network::Testnet),
            "signet" => Ok(Network::Signet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(RlnError::InvalidRequest),
        }
    }

    fn parse_seed_hex(seed_hex: &str) -> Result<[u8; 32], RlnError> {
        let seed_vec = Vec::<u8>::from_hex(seed_hex).map_err(|_| RlnError::InvalidRequest)?;
        let seed: [u8; 32] = seed_vec.try_into().map_err(|_| RlnError::InvalidRequest)?;
        Ok(seed)
    }

    fn random_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        seed
    }

    fn map_bootstrap(data: BootstrapData) -> SdkExternalSignerBootstrap {
        SdkExternalSignerBootstrap {
            node_id: data.identity.node_id,
            account_xpub_vanilla: data.identity.account_xpub_vanilla,
            account_xpub_colored: data.identity.account_xpub_colored,
            master_fingerprint: data.identity.master_fingerprint,
            protocol_version: data.protocol_version,
            api_level: data.api_level,
        }
    }

    fn channel_keys_id_hex_to_dbid(channel_keys_id_hex: &str) -> Result<u64, RlnError> {
        let bytes = Vec::<u8>::from_hex(channel_keys_id_hex).map_err(|_| RlnError::Internal)?;
        if bytes.len() != 32 {
            return Err(RlnError::Internal);
        }
        let mut dbid_bytes = [0u8; 8];
        dbid_bytes.copy_from_slice(&bytes[..8]);
        Ok(u64::from_be_bytes(dbid_bytes))
    }

    fn synthesize_pre_setup_commitment_point(
        &self,
        channel_keys_id_hex: &str,
        idx: u64,
    ) -> Result<SignerResponse, RlnError> {
        let dbid = Self::channel_keys_id_hex_to_dbid(channel_keys_id_hex)?;
        let point_hex = self.transport.synthesize_stub_commitment_point(dbid, idx)?;
        Ok(SignerResponse::Channel(
            ChannelResponse::PerCommitmentPoint { point_hex },
        ))
    }

    fn fallback_response_for_error(
        &self,
        request: &SignerRequest,
    ) -> Result<Option<SignerResponse>, RlnError> {
        match request {
            SignerRequest::Channel(ChannelRequest::Op {
                channel_keys_id_hex,
                op: ChannelOp::GetPerCommitmentPoint { idx },
            }) => self
                .synthesize_pre_setup_commitment_point(channel_keys_id_hex, *idx)
                .map(Some),
            _ => Ok(None),
        }
    }
}

#[uniffi::export]
impl NativeExternalSigner {
    #[uniffi::constructor]
    pub fn new(
        seed_hex: String,
        network: String,
        permissive_policy: Option<bool>,
    ) -> Result<Arc<Self>, RlnError> {
        let network = Self::parse_network(&network)?;
        // Host must supply a stable 32-byte seed (e.g. loaded from Android Keystore / iOS Keychain)
        // and pass it in-memory; this signer helper does not persist secrets.
        let seed = Self::parse_seed_hex(&seed_hex)?;
        let transport = Arc::new(
            InProcessVlsTransport::new(network, seed, permissive_policy.unwrap_or(true))
                .context("native signer transport init failed")
                .map_err(|_| RlnError::Internal)?,
        );
        let backend: Arc<dyn ExternalSignerBackend> = Arc::new(VlsSignerAdapter::new(
            RealVlsClient::new_with_network_and_seed(
                transport.clone(),
                network.to_string(),
                Some(seed),
            ),
        ));
        Ok(Arc::new(Self { backend, transport }))
    }

    pub fn bootstrap(&self) -> Result<SdkExternalSignerBootstrap, RlnError> {
        let bootstrap = match self.backend.call(SignerRequest::Bootstrap).map_err(|e| {
            tracing::error!(error = ?e, "native external signer bootstrap failed");
            RlnError::Internal
        })? {
            signer_external::contract::SignerResponse::Bootstrap(data) => data,
            other => {
                tracing::error!(response = ?other, "native external signer returned non-bootstrap response");
                return Err(RlnError::Internal);
            }
        };
        Ok(Self::map_bootstrap(bootstrap))
    }
}

impl ExternalSignerHost for NativeExternalSigner {
    fn call(&self, request: Vec<u8>) -> Result<Vec<u8>, RlnError> {
        let signer_request: SignerRequest = decode_signer_request(&request).map_err(|e| {
            tracing::error!(error = ?e, "native external signer protobuf decode failed");
            RlnError::Internal
        })?;
        let signer_response = match self.backend.call(signer_request.clone()) {
            Ok(response) => response,
            Err(e) => {
                if let Some(fallback) = self.fallback_response_for_error(&signer_request)? {
                    tracing::debug!(
                        ?fallback,
                        "native external signer backend fallback response"
                    );
                    fallback
                } else {
                    tracing::error!(error = ?e, "native external signer backend call failed");
                    return Err(RlnError::Internal);
                }
            }
        };
        encode_signer_response(&signer_response).map_err(|e| {
            tracing::error!(error = %e, "native external signer response encode failed");
            RlnError::Internal
        })
    }
}
