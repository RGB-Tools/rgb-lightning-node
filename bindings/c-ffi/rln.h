#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


typedef enum CResultValue {
  Ok,
  Err,
} CResultValue;

typedef struct COpaqueStruct {
  const void *ptr;
  uint64_t ty;
} COpaqueStruct;

typedef struct CResultString {
  enum CResultValue result;
  char *inner;
} CResultString;

typedef struct CResult {
  enum CResultValue result;
  struct COpaqueStruct inner;
} CResult;

/**
 * Drop a `NativeExternalSigner` handle. Safe to call immediately after
 * attach / init / unlock succeeds: RLN holds its own `Arc` clone.
 */
void free_native_external_signer(struct COpaqueStruct obj);

void free_sdk_node(struct COpaqueStruct obj);

struct CResultString rln_address(const struct COpaqueStruct *node);

struct CResultString rln_asset_balance(const struct COpaqueStruct *node, const char *asset_id);

struct CResultString rln_asset_metadata(const struct COpaqueStruct *node, const char *asset_id);

struct CResultString rln_btc_balance(const struct COpaqueStruct *node, bool skip_sync);

struct CResultString rln_cancel_hodl_invoice(const struct COpaqueStruct *node,
                                             const char *request_json);

struct CResultString rln_check_indexer_url(const struct COpaqueStruct *node,
                                           const char *indexer_url);

struct CResultString rln_check_proxy_endpoint(const struct COpaqueStruct *node,
                                              const char *proxy_endpoint);

struct CResultString rln_claim_hodl_invoice(const struct COpaqueStruct *node,
                                            const char *request_json);

struct CResultString rln_close_channel(const struct COpaqueStruct *node, const char *request_json);

struct CResultString rln_connect_peer(const struct COpaqueStruct *node,
                                      const char *peer_pubkey_and_addr);

struct CResultString rln_create_utxos(const struct COpaqueStruct *node, const char *request_json);

struct CResultString rln_decode_ln_invoice(const struct COpaqueStruct *node, const char *invoice);

struct CResultString rln_decode_rgb_invoice(const struct COpaqueStruct *node, const char *invoice);

struct CResultString rln_disconnect_peer(const struct COpaqueStruct *node,
                                         const char *request_json);

struct CResultString rln_estimate_fee(const struct COpaqueStruct *node, uint16_t blocks);

struct CResultString rln_fail_transfers(const struct COpaqueStruct *node, const char *request_json);

/**
 * Free a string previously returned in `CResultString.inner`.
 */
void rln_free_string(char *s);

struct CResultString rln_get_asset_media(const struct COpaqueStruct *node, const char *digest);

struct CResultString rln_get_channel_id(const struct COpaqueStruct *node,
                                        const char *temporary_channel_id_hex);

struct CResultString rln_get_payment(const struct COpaqueStruct *node,
                                     const char *payment_hash_hex,
                                     const char *payment_type);

struct CResultString rln_get_swap(const struct COpaqueStruct *node,
                                  const char *payment_hash,
                                  bool taker_flag);

struct CResultString rln_inflate(const struct COpaqueStruct *node, const char *request_json);

struct CResultString rln_invoice_status(const struct COpaqueStruct *node, const char *invoice);

struct CResultString rln_issue_asset_cfa(const struct COpaqueStruct *node,
                                         const char *request_json);

struct CResultString rln_issue_asset_ifa(const struct COpaqueStruct *node,
                                         const char *request_json);

struct CResultString rln_issue_asset_nia(const struct COpaqueStruct *node,
                                         const char *request_json);

struct CResultString rln_issue_asset_uda(const struct COpaqueStruct *node,
                                         const char *request_json);

struct CResultString rln_keysend(const struct COpaqueStruct *node, const char *request_json);

struct CResultString rln_list_assets(const struct COpaqueStruct *node,
                                     const char *filter_asset_schemas_json);

struct CResultString rln_list_channels(const struct COpaqueStruct *node);

struct CResultString rln_list_payments(const struct COpaqueStruct *node);

struct CResultString rln_list_peers(const struct COpaqueStruct *node);

struct CResultString rln_list_swaps(const struct COpaqueStruct *node);

struct CResultString rln_list_transactions(const struct COpaqueStruct *node, bool skip_sync);

struct CResultString rln_list_transfers(const struct COpaqueStruct *node, const char *asset_id);

struct CResultString rln_list_unspents(const struct COpaqueStruct *node, bool skip_sync);

struct CResultString rln_ln_invoice(const struct COpaqueStruct *node, const char *request_json);

struct CResultString rln_maker_execute(const struct COpaqueStruct *node, const char *request_json);

struct CResultString rln_maker_init(const struct COpaqueStruct *node, const char *request_json);

struct CResultString rln_native_external_signer_bootstrap(const struct COpaqueStruct *signer);

struct CResult rln_native_external_signer_new(const char *seed_hex,
                                              const char *network,
                                              bool permissive_policy);

struct CResultString rln_network_info(const struct COpaqueStruct *node);

struct CResultString rln_node_info(const struct COpaqueStruct *node);

struct CResultString rln_open_channel(const struct COpaqueStruct *node, const char *request_json);

struct CResultString rln_post_asset_media(const struct COpaqueStruct *node,
                                          const char *request_json);

struct CResultString rln_refresh_transfers(const struct COpaqueStruct *node,
                                           const char *request_json);

struct CResultString rln_rgb_invoice(const struct COpaqueStruct *node, const char *request_json);

struct CResultString rln_sdk_initialize(const char *request_json);

/**
 * APay receiver-side registration with an LSP. Argument is the LSP's
 * node_id as a hex string (compressed secp256k1). Returns JSON of
 * `AsyncOrderNewResponse` (request_id, host_node_id, protocol_version,
 * order_id, status, accepted_through_index, next_index_expected,
 * unused_hashes, refill_batch_size, first_hash_index). Upstream PR #51.
 */
struct CResultString rln_sdk_node_apay_new(const struct COpaqueStruct *node,
                                           const char *host_node_id);

struct CResultString rln_sdk_node_attach_native_external_signer(const struct COpaqueStruct *node,
                                                                const struct COpaqueStruct *signer);

struct CResultString rln_sdk_node_detach_external_signer(const struct COpaqueStruct *node);

struct CResultString rln_sdk_node_init(const struct COpaqueStruct *node,
                                       const char *password,
                                       const char *mnemonic_opt);

struct CResultString rln_sdk_node_init_with_external_signer(const struct COpaqueStruct *node,
                                                            const char *bootstrap_json);

struct CResultString rln_sdk_node_init_with_native_external_signer(const struct COpaqueStruct *node,
                                                                   const struct COpaqueStruct *signer);

struct CResult rln_sdk_node_new(const char *request_json);

struct CResultString rln_sdk_node_shutdown(const struct COpaqueStruct *node);

struct CResultString rln_sdk_node_unlock(const struct COpaqueStruct *node,
                                         const char *request_json);

struct CResultString rln_sdk_node_unlock_with_attached_external_signer(const struct COpaqueStruct *node,
                                                                       const char *request_json);

struct CResultString rln_sdk_node_unlock_with_native_external_signer(const struct COpaqueStruct *node,
                                                                     const struct COpaqueStruct *signer,
                                                                     const char *request_json);

/**
 * Force an immediate VSS backup flush. Returns `{"version": i64}` JSON
 * where version is the snapshot index just persisted. Throws
 * `FailedVssInit` if VSS isn't configured (vssUrl unset at init) or
 * the flush fails (server unreachable, auth rejected, etc).
 *
 * Useful for app-controlled checkpoints (e.g. "save state before app
 * suspend") rather than relying on the implicit on-write flush. The
 * HTTP equivalent is `POST /vssbackup`; the UniFFI equivalent is
 * `SdkNode::vss_backup()` (uniffi_api/mod.rs:346).
 */
struct CResultString rln_sdk_node_vss_backup(const struct COpaqueStruct *node);

/**
 * Take over a stale VSS ownership fence after a previous node died holding
 * it. Request JSON: `{"password": "..."}`. Returns empty success or
 * `FailedVssInit` if VSS isn't configured / the takeover fails. Pointing
 * two live nodes at the same VSS store corrupts state — only call this
 * when you're certain the previous owner is gone.
 */
struct CResultString rln_sdk_node_vss_clear_fence(const struct COpaqueStruct *node,
                                                  const char *request_json);

struct CResultString rln_sdk_shutdown(void);

struct CResultString rln_send_btc(const struct COpaqueStruct *node, const char *request_json);

struct CResultString rln_send_onion_message(const struct COpaqueStruct *node,
                                            const char *request_json);

struct CResultString rln_send_payment(const struct COpaqueStruct *node, const char *request_json);

struct CResultString rln_send_rgb(const struct COpaqueStruct *node, const char *request_json);

struct CResultString rln_sign_message(const struct COpaqueStruct *node, const char *message);

struct CResultString rln_sync(const struct COpaqueStruct *node);

struct CResultString rln_taker(const struct COpaqueStruct *node, const char *request_json);

struct CResultString rln_uniffi_healthcheck(void);

struct CResultString rln_uniffi_is_initialized(void);
