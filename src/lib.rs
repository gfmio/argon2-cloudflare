use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use worker::Context;
use worker::Env;
use worker::Method;
use worker::Request;
use worker::Response;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use serde_wasm_bindgen::{to_value, from_value};

// HTTP

#[cfg(feature = "http")]
#[worker::event(fetch)]
async fn main(req: Request, _env: Env, _ctx: Context) -> worker::Result<Response> {
    let result = match (req.method(), req.path().as_ref()) {
        (Method::Post, "/hash") => hash_handler(req).await,
        (Method::Post, "/verify") => verify_handler(req).await,
        _ => Err(Error::InvalidRoute),
    };

    match result {
        Ok(body) => Response::ok(body),
        Err(err) => err.to_response(),
    }
}

// RPC

#[cfg(feature = "rpc")]
#[wasm_bindgen]
pub fn hash(request: JsValue) -> Result<JsValue, JsValue> {
    let hash_request: HashRequest = from_value(request).map_err(|err| err.to_string())?;
    let result = hash_password(&hash_request.password, hash_request.options).map_err(|err| err.to_string())?;
    let output = HashResponse { hash: result };
    to_value(&output).map_err(|err| to_value(&err.to_string()).unwrap())
}

#[cfg(feature = "rpc")]
#[wasm_bindgen]
pub fn verify(request: JsValue) -> Result<JsValue, JsValue> {
    let verify_request: VerifyRequest = from_value(request).map_err(|err| err.to_string())?;
    let result = verify_password(&verify_request).map_err(|err| err.to_string())?;
    let output = VerifyResponse { matches: result };
    to_value(&output).map_err(|err| to_value(&err.to_string()).unwrap())
}

// HASH

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashRequest {
    pub password: String,
    pub options: Option<HashOptions>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashOptions {
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashResponse {
    pub hash: String,
}

async fn hash_handler(mut req: Request) -> Result<String, Error> {
    let hash_req: HashRequest = req
        .json()
        .await
        .map_err(|err| Error::DecodeBody(err.to_string()))?;

    let password_hash = hash_password(&hash_req.password, hash_req.options)?;

    let hash_response = HashResponse {
        hash: password_hash,
    };
    serde_json::to_string(&hash_response).map_err(|err| Error::EncodeBody(err.to_string()))
}

fn hash_password(password: &str, options: Option<HashOptions>) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = match options {
        Some(opts) => {
            let params = Params::new(opts.memory_cost, opts.time_cost, opts.parallelism, None)
                .map_err(|err| Error::HashOptions(err.to_string()))?;

            Ok(Argon2::new(
                argon2::Algorithm::Argon2id,
                Version::default(),
                params,
            ))
        }

        None => Ok(Argon2::default()),
    }?;

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|password_hash| password_hash.to_string())
        .map_err(|err| Error::Hash(err.to_string()))
}

// VERIFY

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    pub password: String,
    pub hash: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub matches: bool,
}

async fn verify_handler(mut req: Request) -> Result<String, Error> {
    let options: VerifyRequest = req
        .json()
        .await
        .map_err(|err| Error::DecodeBody(err.to_string()))?;

    let matches = verify_password(&options)?;
    let verify_response = VerifyResponse { matches };
    serde_json::to_string(&verify_response).map_err(|err| Error::EncodeBody(err.to_string()))
}

fn verify_password(options: &VerifyRequest) -> Result<bool, Error> {
    let password_hash = PasswordHash::new(&options.hash)
        .map_err(|err| Error::InvalidPasswordHash(err.to_string()))?;

    let argon2 = Argon2::default();

    match argon2.verify_password(options.password.as_bytes(), &password_hash) {
        Ok(()) => Ok(true),

        Err(err) => match err {
            argon2::password_hash::Error::Password => Ok(false),
            _ => Err(Error::Verify(err.to_string())),
        },
    }
}

// ERROR

enum Error {
    InvalidRoute,
    DecodeBody(String),
    EncodeBody(String),
    HashOptions(String),
    Hash(String),
    InvalidPasswordHash(String),
    Verify(String),
}

impl Error {
    fn to_string(&self) -> String {
        match self {
            Error::InvalidRoute => "Route not found".to_string(),
            Error::DecodeBody(err) => format!("Failed to decode request body: {}", err),
            Error::EncodeBody(err) => format!("Failed to encode response body: {}", err),
            Error::HashOptions(err) => format!("Invalid hash options: {}", err),
            Error::Hash(err) => format!("Failed to hash password: {}", err),
            Error::InvalidPasswordHash(err) => format!("Invalid password hash: {}", err),
            Error::Verify(err) => format!("Failed to verify password: {}", err),
        }
    }
    fn to_response(&self) -> worker::Result<Response> {
        match self {
            Error::InvalidRoute => Response::error("Route not found", 404),
            Error::DecodeBody(err) => {
                Response::error(format!("Failed to decode request body: {}", err), 400)
            }
            Error::EncodeBody(err) => {
                Response::error(format!("Failed to encode response body: {}", err), 500)
            }
            Error::HashOptions(err) => {
                Response::error(format!("Invalid hash options: {}", err), 400)
            }
            Error::Hash(err) => Response::error(format!("Failed to hash password: {}", err), 500),
            Error::InvalidPasswordHash(err) => {
                Response::error(format!("Invalid password hash: {}", err), 400)
            }
            Error::Verify(err) => {
                Response::error(format!("Failed to verify password: {}", err), 500)
            }
        }
    }
}
