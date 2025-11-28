use axum::{http::{header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE}, HeaderValue, Method},Extension, Router};
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::filter::LevelFilter;
use tower_http::cors::CorsLayer;

use crate::{config::Config, db::DBClient};

mod config;
mod dtos;
mod models;
mod error;
mod db;
#[derive(Clone, Debug)]
pub  struct AppState {
    pub env: Config,
    pub db_client: DBClient,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
    .with_max_level(LevelFilter::DEBUG)
    .init();

    dotenv().ok();

    let config = Config::init();
    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("✅ Database pool created successfully.");
            pool
        },
        Err(e) => {
            println!("❌ Failed to create database pool: {:?}", e);
            std::process::exit(1);
        }
    };

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
        .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT])
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE]);

    let db_client = DBClient::new(pool);
    let app_state = AppState {
        env: config.clone(),
        db_client,
    };

    let app: Router = Router::new()
        .layer(Extension(app_state))
        .layer(cors.clone());

    println!(
        "{}"
        ,format!("🚀 Server running at http://localhost:{}", config.port)
    );

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", &config.port))
        .await
        .expect("❌ Failed to bind to address");

    axum::serve(listener, app).await.unwrap();  
}
