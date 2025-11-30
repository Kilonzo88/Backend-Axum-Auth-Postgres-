use lettre::{
    message::{header, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use thiserror::Error;
use tokio::fs;

use crate::config::SmtpConfig;

#[derive(Error, Debug)]
pub enum EmailError {
    #[error("Failed to read template: {0}")]
    TemplateRead(#[from] std::io::Error),

    #[error("Invalid email address: {0}")]
    InvalidAddress(#[from] lettre::address::AddressError),

    #[error("Failed to build email: {0}")]
    EmailBuild(#[from] lettre::error::Error),

    #[error("SMTP transport error: {0}")]
    SmtpTransport(#[from] lettre::transport::smtp::Error),
}

/// Sends an HTML email using SMTP with template support.
///
/// # Arguments
/// * `smtp_config` - SMTP server configuration
/// * `to_email` - Recipient email address
/// * `subject` - Email subject line
/// * `template_path` - Path to HTML template file
/// * `placeholders` - Key-value pairs for template substitution (e.g., `[("{{name}}", "Alice")]`)
///
/// # Errors
/// Returns `EmailError` if:
/// - Template file cannot be read
/// - Email addresses are invalid
/// - SMTP connection or authentication fails
///
/// # Example
/// ```rust
/// use crate::config::SmtpConfig; // Assuming SmtpConfig is in crate::config
/// use super::send_mail; // Assuming send_mail is in the same module
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let smtp_config = SmtpConfig {
///         smtp_username: "test@example.com".to_string(),
///         smtp_password: "password".to_string(),
///         smtp_server: "smtp.example.com".to_string(),
///         smtp_port: 587,
///         from_email: "noreply@example.com".to_string(),
///     };
///
///     send_mail(
///         &smtp_config,
///         "user@example.com",
///         "Welcome!",
///         "templates/welcome.html", // Make sure this path is correct or create the file
///         &[("{{username}}".to_string(), "Alice".to_string())]
///     ).await?;
///     Ok(())
/// }
/// ```
pub async fn send_mail(
    smtp_config: &SmtpConfig,
    to_email: &str,
    subject: &str,
    template_path: &str,
    placeholders: &[(String, String)],
) -> Result<(), EmailError> {
    // Read and process template
    let mut html_template = fs::read_to_string(template_path).await?;
    for (key, value) in placeholders {
        html_template = html_template.replace(key, value);
    }

    // Build email message
    let email = Message::builder()
        .from(smtp_config.from_email.parse()?)
        .to(to_email.parse()?)
        .subject(subject)
        .header(header::ContentType::TEXT_HTML)
        .singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_HTML)
                .body(html_template),
        )?;

    // Setup SMTP transport with credentials
    let creds = Credentials::new(
        smtp_config.smtp_username.clone(),
        smtp_config.smtp_password.clone(),
    );
    
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_config.smtp_server)?
        .credentials(creds)
        .port(smtp_config.smtp_port)
        .timeout(Some(std::time::Duration::from_secs(30)))
        .build();

    // Send email and propagate error
    mailer.send(email).await?;

    Ok(())
}