use std::sync::Arc;

use axum::{
    extract::{Request, State},  // Added State
    http::{header, StatusCode}, // Added header and StatusCode
    middleware::Next,
    response::IntoResponse,
};

use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use uuid::Uuid; // Added Uuid

use crate::{
    db::UserExt,                      // Added UserExt
    error::{ErrorMessage, HttpError}, // Added ErrorMessage
    models::{User, UserRole},
    utils::token, // Added token
    AppState,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWTAuthMiddleware {
    //Authenticated user data
    pub user: User,
}

/*
1. Extract token from cookie/header
   token = "eyJhbGci..."
      ↓
2. Decode JWT
   user_id_string = "550e8400-e29b-41d4-a716-446655440000"
      ↓
3. Parse to UUID
   user_id = Uuid(550e8400-e29b-41dd4-a716-446655440000)
      ↓
4. Query database
   SELECT * FROM users WHERE id = ?
      ↓
5. User found?
   Yes → user = User { id, name, email, role, ... }
   No → Return 401 "User no longer exists"
      ↓
6. Attach to request
   req.extensions = { JWTAuthMiddleware { user } }
      ↓
7. Continue to next handler
   Ok(next.run(req).await)
*/
pub async fn auth(
    cookie_jar: CookieJar,
    State(app_state): State<Arc<AppState>>, // Changed Extension to State and removed _
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, HttpError> {
    let token = cookie_jar
        .get("token")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| {
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|auth_header| auth_header.to_str().ok())
                .and_then(|auth_value| {
                    if auth_value.starts_with("Bearer ") {
                        Some(auth_value[7..].to_owned())
                    } else {
                        None
                    }
                })
        });

    let token = token.ok_or_else(|| HttpError::unauthorized(ErrorMessage::TokenNotProvided))?;

    let user_id_string = token::decode_token(token, app_state.env.jwt_secret.as_bytes())?;

    let user_id = Uuid::parse_str(&user_id_string)
        .map_err(|_| HttpError::unauthorized(ErrorMessage::InvalidToken))?;

    let user = app_state
        .db_client
        .get_user(Some(user_id), None, None, None)
        .await
        .map_err(|_| HttpError::unauthorized(ErrorMessage::UserNoLongerExists))?
        .ok_or_else(|| HttpError::unauthorized(ErrorMessage::UserNoLongerExists))?;

    req.extensions_mut()
        .insert(JWTAuthMiddleware { user: user.clone() });

    Ok(next.run(req).await)
}

pub async fn role_check(
    State(_app_state): State<Arc<AppState>>, // Changed app_state to _app_state
    req: Request,
    next: Next,
    required_roles: Vec<UserRole>, // Removed _
) -> Result<impl IntoResponse, HttpError> {
    let user = req
        .extensions()
        .get::<JWTAuthMiddleware>() // Fixed typo JWTAuthMiddeware
        .ok_or_else(|| HttpError::unauthorized(ErrorMessage::UserNotAuthenticated))?;

    if !required_roles.contains(&user.user.role) {
        return Err(HttpError::new(
            ErrorMessage::PermissionDenied,
            StatusCode::FORBIDDEN,
        ));
    }

    Ok(next.run(req).await)
}
