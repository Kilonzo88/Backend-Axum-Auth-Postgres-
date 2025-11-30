use std::sync::Arc;

use axum::{State, Json};
use validator::Validator;

use crate::{dtos::RegisteruserDto, error::HttpError, AppState};

pub fn auth_handler() -> axum::Router {
    axum::Router::new()
        .route("/register", axum::routing::post(register))
        .route("/login", axum::routing::post(login))
        .route("/verify", axum::routing::get(verify_email))
        .route("/forgot-password", axum::routing::post(forgot_password))
        .route("/reset-password", axum::routing::post(reset_password))
}

pub async fn register(
    State(_app_state): State<Arc<AppState>>,
    Json(body): Json<RegisterUserDto>
) {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let verification_token = uuid::Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::hours(24);

    let hash_password = password::hash(&body.password)
            .map_err(|e| HttpError::server_error(e.to_string()))?;

    let result = app_state.db_client
        .save_user(&body.name, &body.email, &hash_password, &verification_token, expires_at)
        .await;

    match result {
        Ok(_user) => {
            let send_email_result = send_verification_email(&body.email, &body.name, &verification_token).await;

            if let Err(e) = send_email_result {
                eprintln!("Failed to send verification email: {}", e);
            }

            Ok((StatusCode::CREATED, Json(Response {
                status: "success",
                message: "Registration successful! Please check your email to verify your account.".to_string()
            })))
        },
        Err(sqlx::Error::Database(db_err)) => {
            if db_err.is_unique_violation() {
                Err(HttpError::unique_constraint_violation(
                    ErrorMessage::EmailExist.to_string(),
                ))
            } else {
                Err(HttpError::server_error(db_err.to_string()))
            }
        }
        Err(e) => Err(HttpError::server_error(e.to_string()))
    }
}

pub async fn login(
    State(app_state): State<Arc<AppState>>,
    Json(body): Json<LoginUserDto>
) {

}

pub async fn verify_email(
    Query(query_params): Query<VerifyEmailQueryDto>,
    State(_app_state): State<Arc<AppState>>
) {
    
}

pub async fn forgot_password(
    State(_app_state): State<Arc<AppState>>,
    Json(body): Json<ForgotPasswordRequestDto>
) {

}

pub async fn reset_password(
    State(app_state): State<Arc<AppState>>,
    Json(body): Json<ResetPasswordRequestDto>
) {

}