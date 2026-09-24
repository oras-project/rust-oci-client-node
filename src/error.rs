use std::error::Error as StdError;
use thiserror::Error;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use oci_client::errors::{
    OciDistributionError as NativeOciDistributionError, OciEnvelope,
    OciErrorCode as NativeOciErrorCode,
};
use oci_client::ParseError as NativeParseError;

// ============================================================================
// OCI Error Code (OCI Distribution Spec)
// ============================================================================

#[napi(string_enum)]
#[derive(Serialize, Deserialize)]
pub enum OciErrorCode {
    BlobUnknown,
    BlobUploadInvalid,
    BlobUploadUnknown,
    DigestInvalid,
    ManifestBlobUnknown,
    ManifestInvalid,
    ManifestUnknown,
    ManifestUnverified,
    NameInvalid,
    NameUnknown,
    NotFound,
    SizeInvalid,
    TagInvalid,
    Unauthorized,
    Denied,
    Unsupported,
    Toomanyrequests,
    #[serde(untagged)]
    Other(String),
}

impl From<&NativeOciErrorCode> for OciErrorCode {
    fn from(code: &NativeOciErrorCode) -> Self {
        match code {
            NativeOciErrorCode::BlobUnknown => Self::BlobUnknown,
            NativeOciErrorCode::BlobUploadInvalid => Self::BlobUploadInvalid,
            NativeOciErrorCode::BlobUploadUnknown => Self::BlobUploadUnknown,
            NativeOciErrorCode::DigestInvalid => Self::DigestInvalid,
            NativeOciErrorCode::ManifestBlobUnknown => Self::ManifestBlobUnknown,
            NativeOciErrorCode::ManifestInvalid => Self::ManifestInvalid,
            NativeOciErrorCode::ManifestUnknown => Self::ManifestUnknown,
            NativeOciErrorCode::ManifestUnverified => Self::ManifestUnverified,
            NativeOciErrorCode::NameInvalid => Self::NameInvalid,
            NativeOciErrorCode::NameUnknown => Self::NameUnknown,
            NativeOciErrorCode::NotFound => Self::NotFound,
            NativeOciErrorCode::SizeInvalid => Self::SizeInvalid,
            NativeOciErrorCode::TagInvalid => Self::TagInvalid,
            NativeOciErrorCode::Unauthorized => Self::Unauthorized,
            NativeOciErrorCode::Denied => Self::Denied,
            NativeOciErrorCode::Unsupported => Self::Unsupported,
            NativeOciErrorCode::Toomanyrequests => Self::Toomanyrequests,
            NativeOciErrorCode::Other(code) => Self::Other(code.clone()),
        }
    }
}

// ============================================================================
// OCI Registry Error (individual error from OCI envelope)
// ============================================================================

#[napi(object)]
#[derive(Serialize, Deserialize)]
pub struct OciRegistryError {
    pub code: OciErrorCode,
    pub message: String,
    pub detail: String,
}

fn convert_envelope(envelope: &OciEnvelope) -> Vec<OciRegistryError> {
    envelope
        .errors
        .iter()
        .map(|e| OciRegistryError {
            code: OciErrorCode::from(&e.code),
            message: e.message.clone(),
            detail: serde_json::to_string(&e.detail).unwrap_or_default(),
        })
        .collect()
}

// ============================================================================
// OciClientError — discriminated union exposed to TypeScript
//
// Each variant mirrors one OciDistributionError variant by name.
// The From impl is exhaustive (no catch-all), so adding a new variant
// to the native crate causes a compile error here.
//
// Serde handles serialization to/from JS via #[serde(tag = "type")].
// ============================================================================

#[napi(discriminant = "type")]
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum OciDistributionError {
    AuthenticationFailure {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    ConfigConversionError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    DigestError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    GenericError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    HeaderValueError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    ImageIndexParsingNoPlatformResolverError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    ImageManifestNotFoundError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
        image: String,
    },
    IncompatibleLayerMediaTypeError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    IoError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    JsonError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    ManifestEncodingError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    ManifestParsingError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    PullNoLayersError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    PushLayerNoDataError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    PushNoDataError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    RegistryError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
        url: String,
        errors: Vec<OciRegistryError>,
    },
    RegistryNoDigestError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    RegistryNoLocationError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    RegistryTokenDecodeError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    RequestError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    #[serde(rename_all = "camelCase")]
    ServerError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
        status_code: u32,
        url: String,
        server_message: String,
    },
    SpecViolationError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    UnauthorizedError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
        url: String,
    },
    UrlParseError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    UnsupportedMediaTypeError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    UnsupportedSchemaVersionError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    VersionedParsingError {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
}

impl From<&NativeOciDistributionError> for OciDistributionError {
    fn from(err: &NativeOciDistributionError) -> Self {
        let message = err.to_string();
        match err {
            NativeOciDistributionError::AuthenticationFailure(_) => Self::AuthenticationFailure {
                message,
                cause: None,
            },
            NativeOciDistributionError::ConfigConversionError(_) => Self::ConfigConversionError {
                message,
                cause: None,
            },
            NativeOciDistributionError::DigestError(_) => Self::DigestError {
                message,
                cause: None,
            },
            NativeOciDistributionError::GenericError(_) => Self::GenericError {
                message,
                cause: None,
            },
            NativeOciDistributionError::HeaderValueError(_) => Self::HeaderValueError {
                message,
                cause: None,
            },
            NativeOciDistributionError::ImageIndexParsingNoPlatformResolverError => {
                Self::ImageIndexParsingNoPlatformResolverError {
                    message,
                    cause: None,
                }
            }
            NativeOciDistributionError::ImageManifestNotFoundError(image) => {
                Self::ImageManifestNotFoundError {
                    message,
                    cause: None,
                    image: image.clone(),
                }
            }
            NativeOciDistributionError::IncompatibleLayerMediaTypeError(_) => {
                Self::IncompatibleLayerMediaTypeError {
                    message,
                    cause: None,
                }
            }
            NativeOciDistributionError::IoError(_) => Self::IoError {
                message,
                cause: None,
            },
            NativeOciDistributionError::JsonError(_) => Self::JsonError {
                message,
                cause: None,
            },
            NativeOciDistributionError::ManifestEncodingError(_) => Self::ManifestEncodingError {
                message,
                cause: None,
            },
            NativeOciDistributionError::ManifestParsingError(_) => Self::ManifestParsingError {
                message,
                cause: None,
            },
            NativeOciDistributionError::PullNoLayersError => Self::PullNoLayersError {
                message,
                cause: None,
            },
            NativeOciDistributionError::PushLayerNoDataError => Self::PushLayerNoDataError {
                message,
                cause: None,
            },
            NativeOciDistributionError::PushNoDataError => Self::PushNoDataError {
                message,
                cause: None,
            },
            NativeOciDistributionError::RegistryError { envelope, url } => Self::RegistryError {
                message,
                cause: None,
                url: url.clone(),
                errors: convert_envelope(envelope),
            },
            NativeOciDistributionError::RegistryNoDigestError => Self::RegistryNoDigestError {
                message,
                cause: None,
            },
            NativeOciDistributionError::RegistryNoLocationError => Self::RegistryNoLocationError {
                message,
                cause: None,
            },
            NativeOciDistributionError::RegistryTokenDecodeError(_) => {
                Self::RegistryTokenDecodeError {
                    message,
                    cause: None,
                }
            }
            NativeOciDistributionError::RequestError(_) => Self::RequestError {
                message,
                cause: None,
            },
            NativeOciDistributionError::ServerError {
                code,
                url,
                message: server_message,
            } => Self::ServerError {
                message,
                cause: None,
                status_code: *code as u32,
                url: url.clone(),
                server_message: server_message.clone(),
            },
            NativeOciDistributionError::SpecViolationError(_) => Self::SpecViolationError {
                message,
                cause: None,
            },
            NativeOciDistributionError::UnauthorizedError { url } => Self::UnauthorizedError {
                message,
                cause: None,
                url: url.clone(),
            },
            NativeOciDistributionError::UrlParseError(_) => Self::UrlParseError {
                message,
                cause: None,
            },
            NativeOciDistributionError::UnsupportedMediaTypeError(_) => {
                Self::UnsupportedMediaTypeError {
                    message,
                    cause: None,
                }
            }
            NativeOciDistributionError::UnsupportedSchemaVersionError(_) => {
                Self::UnsupportedSchemaVersionError {
                    message,
                    cause: None,
                }
            }
            NativeOciDistributionError::VersionedParsingError(_) => Self::VersionedParsingError {
                message,
                cause: None,
            },
        }
    }
}

#[napi(discriminant = "type")]
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ParseError {
    DigestInvalidFormat {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    DigestInvalidLength {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    DigestUnsupported {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    NameContainsUppercase {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    NameEmpty {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    NameTooLong {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    ReferenceInvalidFormat {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
    TagInvalidFormat {
        message: String,
        #[napi(ts_type = "ErrorCause")]
        cause: Option<Value>,
    },
}

impl From<&NativeParseError> for ParseError {
    fn from(err: &NativeParseError) -> Self {
        let message = err.to_string();
        match err {
            NativeParseError::DigestInvalidFormat => Self::DigestInvalidFormat {
                message,
                cause: None,
            },
            NativeParseError::DigestInvalidLength => Self::DigestInvalidLength {
                message,
                cause: None,
            },
            NativeParseError::DigestUnsupported => Self::DigestUnsupported {
                message,
                cause: None,
            },
            NativeParseError::NameContainsUppercase => Self::NameContainsUppercase {
                message,
                cause: None,
            },
            NativeParseError::NameEmpty => Self::NameEmpty {
                message,
                cause: None,
            },
            NativeParseError::NameTooLong => Self::NameTooLong {
                message,
                cause: None,
            },
            NativeParseError::ReferenceInvalidFormat => Self::ReferenceInvalidFormat {
                message,
                cause: None,
            },
            NativeParseError::TagInvalidFormat => Self::TagInvalidFormat {
                message,
                cause: None,
            },
        }
    }
}

#[napi(object)]
#[derive(Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ErrorCause {
    #[napi(js_name = "type")]
    #[serde(rename = "type")]
    pub type_: String,
    pub message: String,
    pub debug: String,
    pub parsed: Option<Value>,
    #[napi(ts_type = "ErrorCause")]
    pub cause: Option<Value>,
}

#[derive(Debug, Error)]
pub enum NativeBindingError {
    #[error(transparent)]
    Distribution(#[from] NativeOciDistributionError),

    #[error(transparent)]
    Parse(#[from] NativeParseError),
}

#[napi]
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum OciBindingError {
    Distribution(OciDistributionError),
    Parse(ParseError),
}

impl From<&NativeBindingError> for OciBindingError {
    fn from(err: &NativeBindingError) -> Self {
        match err {
            NativeBindingError::Distribution(e) => {
                Self::Distribution(OciDistributionError::from(e))
            }
            NativeBindingError::Parse(e) => Self::Parse(ParseError::from(e)),
        }
    }
}

// ============================================================================
// oci_error — create a stamped JS Error from an OciDistributionError
// ============================================================================

pub(crate) fn oci_error(env: &Env, err: impl Into<NativeBindingError>) -> Error {
    let native_err = err.into();
    let fallback_message = native_err.to_string();
    let client_err = OciBindingError::from(&native_err);
    let js_err = JsError::from(Error::from_reason(&fallback_message)).into_unknown(*env);

    let res: Result<Error> = (|| {
        let mut obj = js_err.coerce_to_object()?;
        if let serde_json::Value::Object(map) =
            serde_json::to_value(&client_err).unwrap_or_default()
        {
            for (key, val) in map {
                let js_val = env.to_js_value(&val)?;
                obj.set_named_property(&key, js_val)?;
            }
        }

        set_cause_chain(env, &mut obj, &native_err);
        Ok(Error::from(js_err))
    })();
    res.unwrap_or_else(|_| Error::from_reason(fallback_message))
}

// ============================================================================
// set_cause_chain — walk Rust source() into nested JS Error.cause
// ============================================================================

fn set_cause_chain(env: &Env, obj: &mut Object, err: &dyn StdError) {
    if let Some(source) = err.source() {
        // 1. Keep cause.message clean for standard JS error assertions
        let source_message = source.to_string();

        // 2. Format the source with Debug ({:?}) - this uses dynamic dispatch!
        let debug_str = format!("{:?}", source);

        if let Ok(mut cause_obj) = Object::new(env) {
            // Explicitly set message as an own property so it survives from_js_value serialization
            let _ = cause_obj.set_named_property("message", env.create_string(source_message));

            // Attach the full automatic Debug output as a property
            let _ = cause_obj.set_named_property("debug", env.create_string(&debug_str));

            let (type_name, json_value) = debug_to_json(&debug_str);
            let _ = cause_obj.set_named_property("type", env.create_string(&type_name));

            // Convert serde_json::Value directly to NAPI JsValue
            if let Ok(js_val) = env.to_js_value(&json_value) {
                let _ = cause_obj.set_named_property("parsed", js_val);
            }

            // Recursively set deeper causes
            set_cause_chain(env, &mut cause_obj, source);

            // Attach cause object to parent
            let _ = obj.set_named_property("cause", cause_obj);
        }
    }
}

/// Non-recursively converts a single `Debug` string level into a `serde_json::Value`.
pub fn debug_to_json(debug_str: &str) -> (String, Value) {
    let s = debug_str.trim();

    // 1. Extract leading Type Name
    let type_re = Regex::new(r"^([a-zA-Z0-9_:]+)").unwrap();
    let type_name = type_re
        .captures(s)
        .map(|cap| cap[1].to_string())
        .unwrap_or_else(|| "Error".into());

    let mut map = Map::new();

    let first_open_paren = s.find('(');
    let first_open_brace = s.find('{');

    // Check whether the outermost container is `{}` or `()`
    let is_named_struct = match (first_open_paren, first_open_brace) {
        (Some(p), Some(b)) => b < p,
        (None, Some(_)) => true,
        _ => false,
    };

    // 2. Named Struct: Type { key: val, ... }
    if is_named_struct {
        if let (Some(open), Some(close)) = (first_open_brace, s.rfind('}')) {
            let body = &s[open + 1..close];
            // Matches key-value pairs while matching nested {}, (), or [] values as single tokens
            let kv_re = Regex::new(
                r#"(\w+):\s*((?:"(?:\\.|[^"\\])*"|\{[^}]*\}|\([^)]*\)|\[[^\]]*\]|[^,()"{}\[\]]+)+)"#,
            )
            .unwrap();

            for cap in kv_re.captures_iter(body) {
                let key = cap[1].to_string();
                let val_raw = cap[2].trim();
                map.insert(key, parse_primitive(val_raw));
            }
            return (type_name, Value::Object(map));
        }
    }
    // 3. Tuple Struct: Type(arg0, arg1, ...)
    else if let (Some(open), Some(close)) = (first_open_paren, s.rfind(')')) {
        let body = &s[open + 1..close];
        // Matches tuple arguments, capturing nested {}, (), or [] blocks whole
        let arg_re =
            Regex::new(r#"(?:"(?:\\.|[^"\\])*"|\{[^}]*\}|\([^)]*\)|\[[^\]]*\]|[^,()"{}\[\]]+)+"#)
                .unwrap();

        let args: Vec<Value> = arg_re
            .find_iter(body)
            .map(|m| parse_primitive(m.as_str().trim()))
            .collect();

        map.insert("args".into(), Value::Array(args));
        return (type_name, Value::Object(map));
    }

    // 4. Fallback for primitives or unit variants
    (type_name, parse_primitive(s))
}

fn parse_primitive(val: &str) -> Value {
    let s = val.trim().trim_matches('"');
    if let Ok(n) = s.parse::<f64>() {
        json!(n)
    } else if let Ok(b) = s.parse::<bool>() {
        json!(b)
    } else {
        json!(s)
    }
}

// ============================================================================
// from_oci_error — read stamped fields from JS Error into OciClientError
// ============================================================================

// ============================================================================
// from_oci_error — read stamped fields from JS Error into OciClientError
// ============================================================================

#[napi]
#[allow(dead_code)]
pub fn from_oci_error(env: Env, err: Unknown) -> Result<Either<OciDistributionError, ParseError>> {
    let Ok(obj) = err.coerce_to_object() else {
        return Ok(Either::A(OciDistributionError::GenericError {
            message: String::from("unable to coerce object to OciDistributionError"),
            cause: None,
        }));
    };

    // Explicitly read non-enumerable `message` and stamped `type` from JS object
    let message = obj
        .get::<String>("message")
        .ok()
        .flatten()
        .unwrap_or_default();

    let Some(type_name) = obj.get::<String>("type").ok().flatten() else {
        return Ok(Either::A(OciDistributionError::GenericError {
            message,
            cause: None,
        }));
    };

    // Construct a JSON map containing `type` and `message`
    let mut map = serde_json::Map::new();
    map.insert("type".to_string(), serde_json::Value::String(type_name));
    map.insert(
        "message".to_string(),
        serde_json::Value::String(message.clone()),
    );

    // Collect all additional stamped properties (e.g., url, statusCode, image, errors)
    if let Ok(names) = obj.get_property_names() {
        for i in 0..names.get_array_length()? {
            let Ok(key) = names.get_element::<String>(i) else {
                continue;
            };
            if key == "type" || key == "message" {
                continue;
            }
            let Ok(Some(val)) = obj.get::<Unknown>(&key) else {
                continue;
            };
            let Ok(json_val) = env.from_js_value::<serde_json::Value, _>(val) else {
                continue;
            };
            map.insert(key, json_val);
        }
    }

    let json_value = serde_json::Value::Object(map);

    // Try deserializing into OciDistributionError first
    if let Ok(dist_err) = serde_json::from_value::<OciDistributionError>(json_value.clone()) {
        return Ok(Either::A(dist_err));
    }

    // Try deserializing into ParseError second
    if let Ok(parse_err) = serde_json::from_value::<ParseError>(json_value) {
        return Ok(Either::B(parse_err));
    }

    // Fallback to GenericError if variant matching fails
    Ok(Either::A(OciDistributionError::GenericError {
        message,
        cause: None,
    }))
}
