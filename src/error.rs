use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)] // Added Clone here
pub enum ErrorMessage {
    EmptyPassword,
    ExceededMaxPasswordLength(usize),
    HashingError,
    InvalidToken,
    ServerError,
    WrongCredentials,
    EmailExists,
    UserNoLongerExists,
    TokenNotProvided,
    PermissionDenied,
    UserNotAuthenticated,
    InvalidHashFormat,
    InternalServerError(String),
    BadRequest(String),
}

impl fmt::Display for ErrorMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorMessage::ServerError => write!(f, "Server Error. Please try again later"),
            ErrorMessage::WrongCredentials => write!(f, "Email or password is wrong"),
            ErrorMessage::EmailExists => write!(f, "A user with this email already exists"),
            ErrorMessage::UserNoLongerExists => {
                write!(f, "User belonging to this token no longer exists")
            }
            ErrorMessage::EmptyPassword => write!(f, "Password cannot be empty"),
            ErrorMessage::HashingError => write!(f, "Error while hashing password"),
            ErrorMessage::InvalidHashFormat => write!(f, "Invalid password hash format"),
            ErrorMessage::ExceededMaxPasswordLength(max_length) => write!(
                f,
                "Password must not be more than {} characters",
                max_length
            ),
            ErrorMessage::InvalidToken => write!(f, "Authentication token is invalid or expired"),
            ErrorMessage::TokenNotProvided => {
                write!(f, "You are not logged in, please provide a token")
            }
            ErrorMessage::PermissionDenied => {
                write!(f, "You are not allowed to perform this action")
            }
            ErrorMessage::UserNotAuthenticated => {
                write!(f, "Authentication required. Please log in.")
            }
            ErrorMessage::InternalServerError(s) => write!(f, "Internal Server Error: {}", s),
            ErrorMessage::BadRequest(s) => write!(f, "Bad Request: {}", s),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpError {
    pub message: ErrorMessage,
    pub status_code: StatusCode,
}

impl HttpError {
    pub fn new(message: ErrorMessage, status_code: StatusCode) -> Self {
        HttpError {
            message,
            status_code,
        }
    }

    pub fn server_error<T: Into<String>>(message: T) -> Self {
        HttpError::new(
            ErrorMessage::InternalServerError(message.into()),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    }

    pub fn bad_request<T: Into<String>>(message: T) -> Self {
        HttpError::new(
            ErrorMessage::BadRequest(message.into()),
            StatusCode::BAD_REQUEST,
        )
    }

    pub fn unique_constraint_violation(message: ErrorMessage) -> Self {
        HttpError::new(message, StatusCode::CONFLICT)
    }

    pub fn unauthorized(message: ErrorMessage) -> Self {
        HttpError::new(message, StatusCode::UNAUTHORIZED)
    }

    pub fn into_http_response(self) -> Response {
        let json_response = Json(ErrorResponse {
            status: "fail".to_string(),
            message: self.message.to_string(),
        });

        (self.status_code, json_response).into_response()
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HttpError: message: {}, status: {}",
            self.status_code, self.message
        )
    }
}

impl std::error::Error for HttpError {}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        self.into_http_response()
    }
}

impl From<ErrorMessage> for HttpError {
    fn from(error_message: ErrorMessage) -> Self {
        let status_code = match error_message {
            ErrorMessage::EmptyPassword => StatusCode::BAD_REQUEST,
            ErrorMessage::ExceededMaxPasswordLength(_) => StatusCode::BAD_REQUEST,
            ErrorMessage::HashingError => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorMessage::InvalidToken => StatusCode::UNAUTHORIZED,
            ErrorMessage::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorMessage::WrongCredentials => StatusCode::UNAUTHORIZED,
            ErrorMessage::EmailExists => StatusCode::CONFLICT,
            ErrorMessage::UserNoLongerExists => StatusCode::UNAUTHORIZED,
            ErrorMessage::TokenNotProvided => StatusCode::UNAUTHORIZED,
            ErrorMessage::PermissionDenied => StatusCode::FORBIDDEN,
            ErrorMessage::UserNotAuthenticated => StatusCode::UNAUTHORIZED,
            ErrorMessage::InvalidHashFormat => StatusCode::INTERNAL_SERVER_ERROR, // Assuming this is a server-side issue
            ErrorMessage::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorMessage::BadRequest(_) => StatusCode::BAD_REQUEST,
        };
        HttpError::new(error_message, status_code)
    }
}

impl From<ErrorMessage> for String {
    fn from(val: ErrorMessage) -> Self {
        val.to_string()
    }
}
