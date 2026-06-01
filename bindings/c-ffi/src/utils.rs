use super::*;

use rgb_lightning_node::NativeExternalSigner;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("Error converting JSON: {0}")]
    JSONConversion(#[from] serde_json::Error),

    #[error("Error converting hex: {0}")]
    HexConversion(String),

    #[error("Error parsing string: {0}")]
    StringParse(String),

    #[error("Error from rgb-lightning-node: {0:?}")]
    Rln(RlnError),

    #[error("Type mismatch")]
    TypeMismatch,

    /// Caught at the FFI boundary by `catch_panic`. Fields: entry-point
    /// label and formatted payload.
    #[error("FFI panic in {0}: {1}")]
    Panic(String, String),
}

impl From<RlnError> for Error {
    fn from(e: RlnError) -> Self {
        Error::Rln(e)
    }
}

impl COpaqueStruct {
    pub(crate) fn new<T: 'static>(other: T) -> Self {
        let mut hasher = DefaultHasher::new();
        TypeId::of::<T>().hash(&mut hasher);
        let ty = hasher.finish();

        COpaqueStruct {
            ptr: Box::into_raw(Box::new(other)) as *const c_void,
            ty,
        }
    }

    pub(crate) fn raw<T>(ptr: *const T) -> Self {
        COpaqueStruct {
            ptr: ptr as *const c_void,
            ty: 0,
        }
    }

    // Public helpers for Rust consumers linking the `rlib` (e.g. the napi-rs
    // binding). C / C++ callers work off the `#[repr(C)]` layout directly.

    pub fn null() -> Self {
        COpaqueStruct {
            ptr: std::ptr::null(),
            ty: 0,
        }
    }

    /// On the `Err` branch of `CResult` / `CResultString`, `inner.ptr` is a
    /// `*mut c_char` pointing at the formatted error message.
    pub fn as_err_string_ptr(&self) -> *mut c_char {
        self.ptr as *mut c_char
    }
}

pub(crate) trait CReturnType: Sized + 'static {
    #[allow(clippy::mut_from_ref)]
    fn from_opaque(other: &COpaqueStruct) -> Result<&mut Self, Error> {
        let mut hasher = DefaultHasher::new();
        TypeId::of::<Self>().hash(&mut hasher);
        let ty = hasher.finish();

        if other.ty != ty {
            return Err(Error::TypeMismatch);
        }

        let boxed = unsafe { Box::from_raw(other.ptr as *mut Self) };
        Ok(Box::leak(boxed))
    }
}
impl CReturnType for SdkNode {}
impl CReturnType for Arc<NativeExternalSigner> {}

// Always drain the per-thread APIError detail slot so it stays one-shot —
// stale residue must never leak into an unrelated later error.
fn format_error_for_ffi(e: &Error) -> String {
    let stashed = rgb_lightning_node::take_last_api_error_detail();
    match e {
        Error::Rln(inner) => {
            let tag = rln_variant_tag(inner);
            match stashed {
                Some(detail) => format!("Rln({tag}): {detail}"),
                None => format!("Rln({tag}): {inner}"),
            }
        }
        other => format!("{other}"),
    }
}

/// Typed match (not `format!("{:?}")`) so a `RlnError` rename is a
/// compile error here rather than a silent downstream string mismatch.
fn rln_variant_tag(e: &RlnError) -> &'static str {
    match e {
        RlnError::NotInitialized => "NotInitialized",
        RlnError::InvalidRequest => "InvalidRequest",
        RlnError::NotFound => "NotFound",
        RlnError::Conflict => "Conflict",
        RlnError::Internal => "Internal",
    }
}

impl<T: 'static> From<Result<T, Error>> for CResult {
    fn from(other: Result<T, Error>) -> Self {
        match other {
            Ok(d) => {
                // Drain on success too so stale residue can't poison the next failure.
                let _ = rgb_lightning_node::take_last_api_error_detail();
                CResult {
                    result: CResultValue::Ok,
                    inner: COpaqueStruct::new(d),
                }
            }
            Err(e) => CResult {
                result: CResultValue::Err,
                inner: COpaqueStruct::raw(string_to_ptr(format_error_for_ffi(&e))),
            },
        }
    }
}

impl From<Result<String, Error>> for CResultString {
    fn from(other: Result<String, Error>) -> Self {
        match other {
            Ok(d) => {
                let _ = rgb_lightning_node::take_last_api_error_detail();
                CResultString {
                    result: CResultValue::Ok,
                    inner: string_to_ptr(d),
                }
            }
            Err(e) => CResultString {
                result: CResultValue::Err,
                inner: string_to_ptr(format_error_for_ffi(&e)),
            },
        }
    }
}

impl From<Result<(), Error>> for CResultString {
    fn from(other: Result<(), Error>) -> Self {
        match other {
            Ok(()) => {
                let _ = rgb_lightning_node::take_last_api_error_detail();
                CResultString {
                    result: CResultValue::Ok,
                    inner: null_mut(),
                }
            }
            Err(e) => CResultString {
                result: CResultValue::Err,
                inner: string_to_ptr(format_error_for_ffi(&e)),
            },
        }
    }
}

pub(crate) fn ptr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
}

pub(crate) fn string_to_ptr(other: String) -> *mut c_char {
    let cstr = match CString::new(other) {
        Ok(cstr) => cstr,
        Err(_) => CString::new(String::from(
            "Error converting string: contains a null-char",
        ))
        .unwrap(),
    };

    cstr.into_raw()
}

pub(crate) fn convert_optional_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        Some(ptr_to_string(ptr))
    }
}

pub(crate) fn require_handle(node: &COpaqueStruct) -> Result<&mut SdkNode, Error> {
    SdkNode::from_opaque(node)
}

/// Catch panics at the FFI boundary so unwinding doesn't cross `extern "C"`
/// and trigger `panic_cannot_unwind`.
///
/// Two safeguards prevent a generic-inlining version of this function from
/// letting LLVM elide the `__rust_try` landing pad entirely (which would
/// silently re-introduce the abort). Don't remove either:
///   1. `#[inline(never)]` keeps a real frame with its own landing pad.
///   2. `&mut dyn FnMut` erases the closure to a vtable, so the call can't
///      be statically proven nounwind.
///
/// `AssertUnwindSafe` is required because callers capture `&COpaqueStruct`
/// and `*const c_char`. Safe in practice: SdkNode's own Mutex/RwLock
/// poisoning logic handles state inconsistency.
#[inline(never)]
pub(crate) fn catch_panic<T>(
    label: &'static str,
    f: &mut dyn FnMut() -> Result<T, Error>,
) -> Result<T, Error> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f())) {
        Ok(r) => r,
        Err(payload) => {
            let msg = panic_payload_to_string(&payload);
            // tracing may be filtered out; stderr is the reliable sink.
            eprintln!("[rln c-ffi] panic in {label}: {msg}");
            Err(Error::Panic(label.to_string(), msg))
        }
    }
}

fn panic_payload_to_string(payload: &Box<dyn std::any::Any + Send + 'static>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "panic with non-string payload".to_string()
}

pub(crate) fn require_signer(
    signer: &COpaqueStruct,
) -> Result<&mut Arc<NativeExternalSigner>, Error> {
    <Arc<NativeExternalSigner>>::from_opaque(signer)
}
