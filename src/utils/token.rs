use axum::http::StatusCode;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm}; // Added decode, encode
use serde::{Deserialize, Serialize};
use tracing; // Added tracing import

use crate::error::{HttpError, ErrorMessage};

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
}

pub fn create_token(
    user_id: String,
    secret: &[u8],
    expires_in_seconds: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let user_id = user_id.trim();
    if user_id.is_empty() {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidSubject.into());
    }
    if expires_in_seconds <= 0 {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into()); // Changed InvalidData to InvalidToken
    }

    let now = Utc::now();
    let iat = now.timestamp();
    let exp = (now + Duration::seconds(expires_in_seconds)).timestamp();
    let claims = TokenClaims {
        sub: user_id.to_string(),
        iat,
        exp,
    };

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
}

pub fn decode_token<T: Into<String>>( // Made generic
    token: T,
    secret: &[u8],
) -> Result<String, HttpError> {
    let validation = Validation::new(Algorithm::HS256);
    let decoded_token = decode::<TokenClaims>(
        &token.into(), // Used .into()
        &DecodingKey::from_secret(secret),
        &validation,
    );

    match decoded_token {
        Ok(token_data) => Ok(token_data.claims.sub),
        Err(e) => {
            tracing::error!("Failed to decode token: {:?}", e); // Log the specific error
            Err(HttpError::new(ErrorMessage::InvalidToken, StatusCode::UNAUTHORIZED))
        }
    }
}