use std::sync::Arc;

use axum::{extract::{Query, State}, http::StatusCode, response::IntoResponse, Json, Router};
use chrono::{Duration, Utc};
use validator::Validate;
use tracing::error;

use crate::{
    db::UserExt,
    dtos::{
        ForgotPasswordRequestDto, LoginUserDto, RegisteredUserDto, ResetPasswordRequestDto,
        Response, VerifyEmailQueryDto,
    },
    error::{ErrorMessage, HttpError},
    mail::send_mail::{send_mail, VerificationEmailContext},
    utils::password,
    AppState,
};

pub fn auth_handler() -> Router<Arc<AppState>> {
    Router::new()
        .route("/register", axum::routing::post(register))
        .route("/login", axum::routing::post(login))
        .route("/verify", axum::routing::get(verify_email))
        .route("/forgot-password", axum::routing::post(forgot_password))
        .route("/reset-password", axum::routing::post(reset_password))
}

pub async fn register(
    State(app_state): State<Arc<AppState>>,
    Json(body): Json<RegisteredUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let verification_token = uuid::Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::hours(24);

    let hash_password =
        password::hash(&body.password).map_err(|e| HttpError::server_error(e.to_string()))?;

    let result = app_state
        .db_client
        .save_user(
            &body.name,
            &body.email,
            &hash_password,
            &verification_token,
            expires_at,
        )
        .await;

    match result {
        Ok(_user) => {
            let app_state_clone = app_state.clone();
            let email_to = body.email.clone();
            let user_name = body.name.clone();
            let base_url = app_state.env.base_url.clone();

            tokio::spawn(async move {
                let verification_url = format!("{}/api/auth/verify?token={}", base_url, verification_token);
                let context = VerificationEmailContext {
                    name: user_name,
                    verification_url,
                };

                let send_email_result = send_mail(
                    &app_state_clone.env.smtp_config,
                    &email_to,
                    "Verify your email",
                    "verification_email.html",
                    &context,
                )
                .await;

                if let Err(e) = send_email_result {
                    error!("Failed to send verification email: {}", e);
                }
            });

            Ok((
                StatusCode::CREATED,
                Json(Response {
                    status: "success",
                    message: "Registration successful! Please check your email to verify your account."
                        .to_string(),
                }),
            ))
        }
        Err(sqlx::Error::Database(db_err)) => {
            if db_err.is_unique_violation() {
                Err(HttpError::unique_constraint_violation(
                    ErrorMessage::EmailExists,
                ))
            } else {
                Err(HttpError::server_error(db_err.to_string()))
            }
        }
        Err(e) => Err(HttpError::server_error(e.to_string())),
    }
}

pub async fn login(
    State(_app_state): State<Arc<AppState>>,
    Json(_body): Json<LoginUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    Ok((StatusCode::OK, "Login successful"))
}

pub async fn verify_email(
    Query(_query_params): Query<VerifyEmailQueryDto>,
    State(_app_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    Ok((StatusCode::OK, "Email verified"))
}

pub async fn forgot_password(
    State(_app_state): State<Arc<AppState>>,
    Json(_body): Json<ForgotPasswordRequestDto>,
) -> Result<impl IntoResponse, HttpError> {
    Ok((StatusCode::OK, "Password reset email sent"))
}

pub async fn reset_password(
    State(_app_state): State<Arc<AppState>>,
    Json(_body): Json<ResetPasswordRequestDto>,
) -> Result<impl IntoResponse, HttpError> {
    Ok((StatusCode::OK, "Password reset successful"))
}