use crate::config::SmtpConfig;
use lazy_static::lazy_static;
use lettre::{
    message::{header, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::Serialize;
use tera::{Context, Tera};
use thiserror::Error;

lazy_static! {
    pub static ref TEMPLATES: Tera = {
        let mut tera = match Tera::new("templates/**/*.html") {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {}", e);
                ::std::process::exit(1);
            }
        };
        tera.autoescape_on(vec![".html"]);
        tera
    };
}

#[derive(Serialize, Debug, Clone)]
pub struct VerificationEmailContext {
    pub username: String,
    pub verification_link: String,
}

#[derive(Error, Debug)]
pub enum EmailError {
    #[error("Template error: {0}")]
    TemplateError(#[from] tera::Error),

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
/// * `template_name` - The name of the template file in the `templates` directory
/// * `context` - The context to be rendered in the template
///
/// # Errors
/// Returns `EmailError` if:
/// - Template rendering fails
/// - Email addresses are invalid
/// - SMTP connection or authentication fails
pub async fn send_mail<T: Serialize>(
    smtp_config: &SmtpConfig,
    to_email: &str,
    subject: &str,
    template_name: &str,
    context: &T,
) -> Result<(), EmailError> {
    let context = Context::from_serialize(context)?;
    let html_template = TEMPLATES.render(template_name, &context)?;

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

    let creds = Credentials::new(
        smtp_config.smtp_username.clone(),
        smtp_config.smtp_password.clone(),
    );

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_config.smtp_server)?
        .credentials(creds)
        .port(smtp_config.smtp_port)
        .timeout(Some(std::time::Duration::from_secs(30)))
        .build();

    mailer.send(email).await?;

    Ok(())
}
