use chrono::{DateTime, Utc};
use core::str;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

use crate::models::{User, UserRole};
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
#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct LoginUserDto {
    #[validate(length(min = 1, message = "Email is required"), email(message = "Email is invalid"))]
    pub email: String,
    #[validate(length(min = 6, message = "Password must be at least 6 characters"))]
    pub password: String,
}

#[derive(Serialize, Deserialize, Validate)]
pub struct RequestQueryDto {
    #[validate(range(min = 1))]
    pub page: Option<usize>,
    #[validate(range(min = 1, max = 50))]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilterUserDto {
    pub id: String,
    pub username: String,
    pub email: String,
    pub verified: bool,
    pub role: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

impl FilterUserDto {
    pub fn filter_user(user: &User) -> Self {
        FilterUserDto {
            id: user.id.to_string(),
            username: user.username.clone(),
            email: user.email.clone(),
            verified: user.verified,
            role: user.role.to_str().to_string(),
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }

    pub fn filter_users(user: &[User]) -> Vec<FilterUserDto> {
        user.iter().map(|u| Self::filter_user(u)).collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    pub users: FilterUserDto,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponseDto {
    pub status: String,
    pub data: UserData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserListResponseDto {
    pub status: String,
    pub users: Vec<FilterUserDto>,
    pub results: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponseDto {
    pub status: String,
    pub token: String,
}

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]

pub struct NameUpdateDto {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RoleUpdateDto {
    #[validate(custom = "validate_user_role")]
    pub role: UserRole,
}

fn validate_user_role(role: &UserRole) -> Result<(), ValidationError> {
    match role {
        UserRole::Admin | UserRole::User => Ok(()),
        _ => Err(ValidationError::new("Invalid role")),
    }
}
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

#[derive(Serialize, Deserialize, Validate)]
pub struct VerifyEmailQueryDto {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,
}

#[derive(Deserialize, Serialize, Validate, Debug, Clone)]
pub struct ForgotPasswordRequestDto {
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Email is invalid")
    )]
    pub email: String,
}

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
