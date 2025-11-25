use chrono::{DateTime, Utc};
use uuid::Uuid;
use core::str;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::models::{User, UserRole};

/// Data Transfer Object for user registration requests.
#[derive(Debug, Serialize, Deserialize, Validate, Default, Clone)]
pub struct RegisteredUserDto {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Invalid email format")
    )]
    pub email: String,
    #[validate(length(min = 6, message = "Password must be at least 6 characters long"))]
    pub password: String,
    #[validate(
        length(min=1, message = "Confirm Password is required"),
        must_match(other = "password", message = "Passwords do not match")
    )]
    #[serde(rename = "confirmPassword")]
    pub confirm_password: String,
}

/// Data Transfer Object for user login requests.
#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct LoginUserDto {
    #[validate(length(min = 1, message = "Email is required"), email(message = "Email is invalid"))]
    pub email: String,
    #[validate(length(min = 6, message = "Password must be at least 6 characters"))]
    pub password: String,
}

/// Represents pagination parameters from a request's query string.
#[derive(Serialize, Deserialize, Validate)]
pub struct RequestQueryDto {
    #[validate(range(min = 1))]
    pub page: Option<usize>,
    #[validate(range(min = 1, max = 50))]
    pub limit: Option<usize>,
}

/// A public-facing, safe representation of a User, excluding sensitive fields like the password hash.
#[derive(Debug, Serialize, Deserialize)]
pub struct FilterUserDto {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub verified: bool,
    pub role: UserRole,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

impl From<&User> for FilterUserDto {
    fn from(user: &User) -> Self {
        FilterUserDto {
            id: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            verified: user.verified,
            role: user.role,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

impl FilterUserDto {
    /// Converts a slice of User models into a vector of safe-to-send FilterUserDto objects.
    pub fn filter_users(users: &[User]) -> Vec<FilterUserDto> {
        users.iter().map(FilterUserDto::from).collect()
    }
}

/// Wrapper for a single user, used for standardizing API response structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    pub user: FilterUserDto,
}

/// Standard API response for an operation that returns a single user.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponseDto {
    pub status: String,
    pub data: UserData,
}

/// Standard API response for an operation that returns a list of users.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserListResponseDto {
    pub status: String,
    pub users: Vec<FilterUserDto>,
    pub results: i64,
}

/// Standard API response for a successful login, containing the session token.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserLoginResponseDto {
    pub status: String,
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub status: &'static str,
    pub message: String,
}

/// DTO for updating a user's name.
#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct NameUpdateDto {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
}

/// DTO for updating a user's role.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RoleUpdateDto {
    #[validate(length(min = 1, message = "Role is required"))]
    pub role: String,
}

/// DTO for a user to update their own password.
#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct UserPasswordUpdateDto {
    #[validate(length(min = 1, message = "New password is required"))]
    pub new_password: String,
    #[validate(
        length(
            min = 6,
            message = "new password confirm must be at least 6 characters"
        ),
        must_match(other = "new_password", message = "new passwords do not match")
    )]
    pub new_password_confirm: String,

    #[validate(length(min = 6, message = "Old password must be at least 6 characters"))]
    pub old_password: String,
}

/// DTO for the token received from an email verification link's query string.
#[derive(Serialize, Deserialize, Validate)]
pub struct VerifyEmailQueryDto {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,
}

/// DTO for initiating a password reset request via email.
#[derive(Deserialize, Serialize, Validate, Debug, Clone)]
pub struct ForgotPasswordRequestDto {
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Email is invalid")
    )]
    pub email: String,
}

/// DTO for completing a password reset with a token and new password.
#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct ResetPasswordRequestDto {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,

    #[validate(
        length(min = 6, message = "new password must be at least 6 characters")
    )]
    pub new_password: String,

    #[validate(
        length(
            min = 6,
            message = "New password confirm must be at least 6 characters"
        ),
        must_match(other = "new_password", message = "new passwords do not match")
    )]
    pub new_password_confirm: String,
}