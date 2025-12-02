use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    Json, Router,
};
use axum_extra::extract::cookie::Cookie;
use chrono::{Duration, Utc};
use rand::rngs::ThreadRng;
use rand::Rng;
use rand_distr::Alphanumeric;
use tracing::{error, info};
use validator::Validate;

use crate::{
    db::UserExt,
    dtos::{
        ForgotPasswordRequestDto, LoginUserDto, RegisteredUserDto, ResetPasswordRequestDto,
        Response, UserLoginResponseDto, VerifyEmailQueryDto,
    },
    error::{ErrorMessage, HttpError},
    mail::mails,
    utils::{password, token},
    AppState,
};

#[derive(Debug, Clone)]
struct EmailJobData {
    app_state: Arc<AppState>,
    email_to: String,
    user_name: String,
    verification_token: String,
}

#[derive(Debug, Clone)]
struct PasswordResetEmailJobData {
    app_state: Arc<AppState>,
    email_to: String,
    user_name: String,
    reset_link: String,
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
            if db_err
                .as_database_error()
                .is_some_and(|e| e.is_unique_violation())
            {
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
        info!(
            "Attempting to send verification email to {}",
            email_job_data.email_to
        );
        match mails::send_verification_email(
            &email_job_data.app_state.env.smtp_config,
            &email_job_data.email_to,
            &email_job_data.user_name,
            &email_job_data.verification_token,
            &email_job_data.app_state.env.base_url,
        )
        .await
        {
            Ok(_) => info!("Verification email sent to {}", email_job_data.email_to),
            Err(e) => error!(
                "Failed to send verification email to {}: {}",
                email_job_data.email_to, e
            ),
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
    State(app_state): State<Arc<AppState>>,
    Json(body): Json<LoginUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    // Step 1: Validation
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    // Step 2: Retrieve user from database
    let result = app_state
        .db_client
        .get_user(None, None, Some(&body.email), None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::bad_request(
        ErrorMessage::WrongCredentials.to_string(),
    ))?;
    // Step 3: Verify password
    let password_matched = password::compare(&body.password, &user.password)
        .map_err(|_| HttpError::bad_request(ErrorMessage::WrongCredentials.to_string()))?;

    // Step 4: If Valid, Create Token & Cookie
    if password_matched {
        let token = token::create_token(
            user.id.to_string(),
            app_state.env.jwt_secret.as_bytes(),
            app_state.env.jwt_maxage,
        )
        .map_err(|e| HttpError::server_error(e.to_string()))?;

        let cookie_duration = time::Duration::minutes(app_state.env.jwt_maxage * 60);
        let cookie = Cookie::build(("token", token.clone()))
            .path("/")
            .max_age(cookie_duration)
            .http_only(true)
            .build();

        // Step 5: Build Response
        let response = axum::response::Json(UserLoginResponseDto {
            status: "success".to_string(),
            token,
        });

        let mut headers = HeaderMap::new();

        headers.append(header::SET_COOKIE, cookie.to_string().parse().unwrap());

        let mut response = response.into_response();
        response.headers_mut().extend(headers);

        Ok(response)

    // Step 6: Invalid → Error
    } else {
        Err(HttpError::bad_request(
            ErrorMessage::WrongCredentials.to_string(),
        ))
    }
}

pub async fn verify_email(
    Query(query_params): Query<VerifyEmailQueryDto>,
    State(app_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    query_params
        .validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let result = app_state
        .db_client
        .get_user(None, None, None, Some(&query_params.token))
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::unauthorized(ErrorMessage::InvalidToken))?;

    if let Some(expires_at) = user.token_expires_at {
        if Utc::now() > expires_at {
            return Err(HttpError::bad_request(
                "Verification token has expired".to_string(),
            ));
        }
    } else {
        return Err(HttpError::bad_request(
            "Invalid verification token".to_string(),
        ));
    }

    app_state
        .db_client
        .verifed_token(&query_params.token)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let send_welcome_email_result =
        mails::send_welcome_email(&app_state.env.smtp_config, &user.email, &user.name).await;

    if let Err(e) = send_welcome_email_result {
        eprintln!("Failed to send welcome email: {}", e);
    }

    let token = token::create_token(
        user.id.to_string(),
        app_state.env.jwt_secret.as_bytes(),
        app_state.env.jwt_maxage,
    )
    .map_err(|e| HttpError::server_error(e.to_string()))?;

    let cookie_duration = time::Duration::minutes(app_state.env.jwt_maxage * 60);
    let cookie = Cookie::build(("token", token.clone()))
        .path("/")
        .max_age(cookie_duration)
        .http_only(true)
        .build();

    let mut headers = HeaderMap::new();

    headers.append(header::SET_COOKIE, cookie.to_string().parse().unwrap());

    let redirect = Redirect::to(app_state.env.frontend_url.as_str());

    let mut response = redirect.into_response();

    response.headers_mut().extend(headers);

    Ok(response)
}

pub async fn forgot_password(
    State(app_state): State<Arc<AppState>>,
    Json(body): Json<ForgotPasswordRequestDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    if let Some(user) = app_state
        .db_client
        .get_user(None, None, Some(&body.email), None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?
    {
        let verification_token: String = ThreadRng::default()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        let expires_at = Utc::now() + Duration::hours(1);

        app_state
            .db_client
            .update_user_verification_token(user.id, &verification_token, expires_at)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;
        
        let reset_link = format!(
            "{}/reset-password?token={}",
            &app_state.env.frontend_url, &verification_token
        );

        let email_job_data = PasswordResetEmailJobData {
            app_state: app_state.clone(),
            email_to: user.email.clone(),
            user_name: user.name.clone(),
            reset_link,
        };

        tokio::spawn(async move {
            info!(
                "Attempting to send password reset email to {}",
                email_job_data.email_to
            );
            match mails::send_forgot_password_email(
                &email_job_data.app_state.env.smtp_config,
                &email_job_data.email_to,
                &email_job_data.user_name,
                &email_job_data.reset_link,
            )
            .await
            {
                Ok(_) => info!(
                    "Password reset email sent to {}",
                    email_job_data.email_to
                ),
                Err(e) => error!(
                    "Failed to send password reset email to {}: {}",
                    email_job_data.email_to, e
                ),
            };
        });
    }

    Ok((
        StatusCode::OK,
        Json(Response {
            status: "success",
            message: "If an account with that email exists, a password reset link has been sent."
                .to_string(),
        }),
    ))
}

pub async fn reset_password(
    State(app_state): State<Arc<AppState>>,
    Json(body): Json<ResetPasswordRequestDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let result = app_state.db_client
        .get_user(None, None, None, Some(&body.token))
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::bad_request("Invalid or expired token".to_string()))?;

    if let Some(expires_at) = user.token_expires_at {
        if Utc::now() > expires_at {
            return Err(HttpError::bad_request("Verification token has expired".to_string()))?;
        }
    }else {
        return Err(HttpError::bad_request("Invalid verification token".to_string()))?;
    }

    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();

    let hash_password = password::hash(&body.new_password)
            .map_err(|e| HttpError::server_error(e.to_string()))?;

    app_state.db_client
        .update_user_password(user_id.clone(), hash_password)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    app_state.db_client
        .verifed_token(&body.token)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = Response {
        message: "Password has been successfully reset.".to_string(),
        status: "success",
    };

    Ok(Json(response))
}
