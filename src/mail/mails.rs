use super::send_mail::{send_mail, VerificationEmailContext, PasswordChangedEmailContext};
use crate::config::SmtpConfig;
use serde::Serialize;
use chrono::Utc;

#[derive(Serialize)]
pub struct WelcomeEmailContext {
    pub username: String,
}

#[derive(Serialize)]
pub struct ForgotPasswordEmailContext {
    pub username: String,
    pub reset_link: String,
}

pub async fn send_verification_email(
    smtp_config: &SmtpConfig,
    to_email: &str,
    username: &str,
    token: &str,
    base_url: &str,
) -> Result<(), super::send_mail::EmailError> {
    let subject = "Email Verification";
    let template_name = "verification_email.html";
    let verification_link = format!("{}/api/auth/verify?token={}", base_url, token);

    let context = VerificationEmailContext {
        username: username.to_string(),
        verification_link,
    };

    send_mail(smtp_config, to_email, subject, template_name, &context).await
}

pub async fn send_welcome_email(
    smtp_config: &SmtpConfig,
    to_email: &str,
    username: &str,
) -> Result<(), super::send_mail::EmailError> {
    let subject = "Welcome to Our Application";
    let template_name = "welcome_email.html";

    let context = WelcomeEmailContext {
        username: username.to_string(),
    };

    send_mail(smtp_config, to_email, subject, template_name, &context).await
}

pub async fn send_forgot_password_email(
    smtp_config: &SmtpConfig,
    to_email: &str,
    username: &str,
    reset_link: &str,
) -> Result<(), super::send_mail::EmailError> {
    let subject = "Reset Your Password";
    let template_name = "reset_password_email.html";

    let context = ForgotPasswordEmailContext {
        username: username.to_string(),
        reset_link: reset_link.to_string(),
    };

    send_mail(smtp_config, to_email, subject, template_name, &context).await
}

/// Sends a password changed confirmation email to the user.
///
/// # Arguments
/// * `smtp_config` - SMTP server configuration
/// * `to_email` - Recipient email address
/// * `username` - User's display name
///
/// # Errors
/// Returns `EmailError` if email sending fails
pub async fn send_password_changed_email(
    smtp_config: &SmtpConfig,
    to_email: &str,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let timestamp = Utc::now().format("%B %d, %Y at %I:%M %p UTC").to_string();
    
    let context = PasswordChangedEmailContext {
        username: username.to_string(),
        timestamp,
    };

    send_mail(
        smtp_config,
        to_email,
        "Password Changed Successfully",
        "Passwordchanged-email.html",
        &context,
    )
    .await?;

    Ok(())
}