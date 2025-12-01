use std::sync::Arc;

use axum::{extract::{Query, State}, http::StatusCode, response::IntoResponse, Json, Router};
use chrono::{Duration, Utc};
use validator::Validate;
use tracing::{error, info};
use rand::Rng;
use rand_distr::Alphanumeric;
use rand::rngs::ThreadRng; // Add this import

use crate::{
    db::UserExt,
    dtos::{
        ForgotPasswordRequestDto, LoginUserDto, RegisteredUserDto, ResetPasswordRequestDto,
        Response, VerifyEmailQueryDto,
    },
    error::{ErrorMessage, HttpError},
    mail::mails,
    utils::password,
    AppState,
};

/// Encapsulates all data needed to send a verification email in a background task.
/// This struct is moved into `tokio::spawn` to avoid lifetime issues.
#[derive(Debug, Clone)]
struct EmailJobData {
    app_state: Arc<AppState>,
    email_to: String,
    user_name: String,
    verification_token: String,
}

/// Helper function to encapsulate user creation and verification logic.
async fn create_user_with_verification(
    app_state: Arc<AppState>,
    body: &RegisteredUserDto,
) -> Result<String, HttpError> {
    let verification_token: String = ThreadRng::default()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let expires_at = Utc::now() + Duration::hours(24);

    let hash_password =
        password::hash(&body.password).map_err(|e| HttpError::server_error(e.to_string()))?;

    app_state
        .db_client
        .save_user(
            &body.name,
            &body.email,
            &hash_password,
            &verification_token,
            expires_at,
        )
        .await
        .map_err(|db_err| {
            if db_err.as_database_error().map_or(false, |e| e.is_unique_violation()) {
                HttpError::unique_constraint_violation(ErrorMessage::EmailExists)
            } else {
                HttpError::server_error(db_err.to_string())
            }
        })?;

    Ok(verification_token)
}

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

    let verification_token = create_user_with_verification(app_state.clone(), &body).await?;

    let email_job_data = EmailJobData {
        app_state: app_state.clone(),
        email_to: body.email.clone(),
        user_name: body.name.clone(),
        verification_token,
    };

    tokio::spawn(async move {
        info!("Attempting to send verification email to {}", email_job_data.email_to);
        match mails::send_verification_email(
            &email_job_data.app_state.env.smtp_config,
            &email_job_data.email_to,
            &email_job_data.user_name,
            &email_job_data.verification_token,
            &email_job_data.app_state.env.base_url,
        )
        .await {
            Ok(_) => info!("Verification email sent to {}", email_job_data.email_to),
            Err(e) => error!("Failed to send verification email to {}: {}", email_job_data.email_to, e),
        };
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