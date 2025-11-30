use std::{env, fs};
use lettre::{
    message::{header, SinglePart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EmailError {
    #[error("Environment variable error: {0}")]
    EnvVar(#[from] env::VarError),
    
    #[error("Failed to read template: {0}")]
    TemplateRead(#[from] std::io::Error),
    
    #[error("Invalid email address: {0}")]
    InvalidAddress(#[from] lettre::address::AddressError),
    
    #[error("Failed to build email: {0}")]
    EmailBuild(#[from] lettre::error::Error),
    
    #[error("SMTP transport error: {0}")]
    SmtpTransport(#[from] lettre::transport::smtp::Error),
    
    #[error("Failed to parse port: {0}")]
    PortParse(#[from] std::num::ParseIntError),
}

pub async fn send_mail(
    to_email: &str,
    subject: &str,
    template_path: &str,
    placeholders: &[(String, String)],
) -> Result<(), EmailError> {
    // Load config
    let smtp_username = env::var("SMTP_USERNAME")?;
    // If fails: VarError → EmailError::EnvVar → returns early
    let smtp_password = env::var("SMTP_PASSWORD")?;
    // If fails: VarError → EmailError::EnvVar → returns early
    let smtp_server = env::var("SMTP_SERVER")?;
    // If fails: VarError → EmailError::EnvVar → returns early
    let smtp_port: u16 = env::var("SMTP_PORT")?.parse()?;
    // If fails: VarError → EmailError::EnvVar → returns early, then ParseIntError → EmailError::PortParse → returns early

    // Read and process template
    let mut html_template = fs::read_to_string(template_path)?;
    for (key, value) in placeholders {
        html_template = html_template.replace(key, value);
    }

    // Build email message
    let email = Message::builder()
        .from(smtp_username.parse()?)
        .to(to_email.parse()?)
        .subject(subject)
        .header(header::ContentType::TEXT_HTML)
        .singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_HTML)
                .body(html_template),
        )?;

    // Setup SMTP transport with credentials
    let creds = Credentials::new(smtp_username, smtp_password);
    let mailer = SmtpTransport::starttls_relay(&smtp_server)?
        .credentials(creds)
        .port(smtp_port)
        .timeout(Some(std::time::Duration::from_secs(30)))  // Add timeout
        .build();

    // Send email and propagate error
    mailer.send(&email)?;

    Ok(())
}