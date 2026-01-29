use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use biscuit_auth::{macros::authorizer, Biscuit, PublicKey};
use std::{collections::HashSet, sync::Arc};

use crate::{
    error::{APIError, AppError},
    utils::{hex_str, hex_str_to_vec, AppState},
};

const READ_ONLY_OPS: [&str; 23] = [
    "/assetbalance",
    "/assetmetadata",
    "/btcbalance",
    "/checkindexerurl",
    "/checkproxyendpoint",
    "/decodelninvoice",
    "/decodergbinvoice",
    "/estimatefee",
    "/getassetmedia",
    "/getchannelid",
    "/getpayment",
    "/getswap",
    "/invoicestatus",
    "/listassets",
    "/listchannels",
    "/listpayments",
    "/listpeers",
    "/listswaps",
    "/listtransactions",
    "/listtransfers",
    "/listunspents",
    "/networkinfo",
    "/nodeinfo",
];

pub(crate) fn check_auth_args(
    disable_authentication: bool,
    root_public_key: Option<String>,
) -> Result<Option<PublicKey>, AppError> {
    match (disable_authentication, root_public_key.is_some()) {
        (true, true) => {
            tracing::error!("Authentication disabled but root key provided");
            return Err(AppError::InvalidAuthenticationArgs);
        }
        (false, false) => {
            tracing::error!("Authentication enabled but no root key provided");
            return Err(AppError::InvalidAuthenticationArgs);
        }
        (true, false) => {
            tracing::info!("Authentication disabled");
        }
        (false, true) => {
            tracing::info!("Authentication enabled");
        }
    };

    Ok(if let Some(root_key_hex) = &root_public_key {
        let key_bytes = hex_str_to_vec(root_key_hex).ok_or(AppError::InvalidRootKey)?;
        if key_bytes.len() != 32 {
            return Err(AppError::InvalidRootKey);
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        let public_key = PublicKey::from_bytes(&key_array, biscuit_auth::Algorithm::Ed25519)
            .map_err(|_| AppError::InvalidRootKey)?;
        Some(public_key)
    } else {
        None
    })
}

pub(crate) async fn conditional_auth_middleware(
    State(app_state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let Some(root_pubkey) = app_state.root_public_key else {
        // if no root key is configured, skip authentication
        return Ok(next.run(request).await);
    };

    let auth_header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let auth_token = match auth_header {
        Some(token) => token,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    // verify the token
    let token =
        Biscuit::from_base64(auth_token, root_pubkey).map_err(|_| StatusCode::UNAUTHORIZED)?;

    if app_state.is_token_revoked(&token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if is_token_expired(&token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if is_admin_role(&token) {
        return Ok(next.run(request).await);
    }

    let op = request.uri().path().to_string();

    if is_read_only_role(&token) {
        if is_operation_readonly(&op) {
            return Ok(next.run(request).await);
        } else {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    if is_custom_role(&token) {
        if is_operation_permitted(&token, &op) {
            return Ok(next.run(request).await);
        } else {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

fn is_admin_role(token: &Biscuit) -> bool {
    is_role(token, "admin")
}

fn is_custom_role(token: &Biscuit) -> bool {
    is_role(token, "custom")
}

fn is_read_only_role(token: &Biscuit) -> bool {
    is_role(token, "read-only")
}

fn is_role(token: &Biscuit, role: &str) -> bool {
    let res = authorizer!(r#"allow if role({role});"#)
        .time()
        .build(token)
        .and_then(|mut authorizer| authorizer.authorize());
    res.is_ok()
}

fn is_operation_permitted(token: &Biscuit, op: &str) -> bool {
    let res = authorizer!(
        r#"
            operation({op});
            allow if right("api", {op});
        "#,
    )
    .time()
    .build(token)
    .and_then(|mut authorizer| authorizer.authorize());
    res.is_ok()
}

fn is_operation_readonly(operation: &str) -> bool {
    READ_ONLY_OPS.contains(&operation)
}

fn is_token_expired(token: &Biscuit) -> bool {
    let res = authorizer!(r#"allow if true;"#)
        .time()
        .build(token)
        .and_then(|mut authorizer| authorizer.authorize());
    res.is_err()
}

impl AppState {
    pub(crate) fn revoke_token(&self, token_to_revoke: &Biscuit) -> Result<(), APIError> {
        let revocation_ids = token_to_revoke.revocation_identifiers();
        let db = self.get_db();

        let mut revoked = self.revoked_tokens.lock().unwrap();
        for id in revocation_ids {
            let token_id_hex = hex_str(&id);
            db.add_revoked_token(&token_id_hex)?;
            revoked.insert(id);
        }

        Ok(())
    }

    fn is_token_revoked(&self, token: &Biscuit) -> bool {
        let revocation_ids: HashSet<_> = token.revocation_identifiers().into_iter().collect();
        let revoked = self.revoked_tokens.lock().unwrap();
        !revocation_ids.is_disjoint(&*revoked)
    }

    pub(crate) fn load_revoked_tokens(&self) -> Result<HashSet<Vec<u8>>, AppError> {
        let db = self.get_db();
        let revoked = db.load_revoked_tokens().map_err(|e| {
            tracing::error!("Failed to load revoked tokens from database: {e:?}");
            AppError::IO(std::io::Error::other(format!(
                "Failed to load revoked tokens: {e:?}"
            )))
        })?;
        tracing::info!("Loaded {} revoked tokens from database", revoked.len());
        Ok(revoked)
    }
}
