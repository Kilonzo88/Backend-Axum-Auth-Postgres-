use axum::{
    extract::State,
    http::{
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method,
    },
    Router,
};
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::CorsLayer;
use tracing_subscriber::filter::LevelFilter;

use crate::{config::Config, db::DBClient};

mod config;
mod db;
mod dtos;
mod error;
mod models;
#[derive(Clone, Debug)]
pub struct AppState {
    pub env: Config,
    pub db_client: DBClient,
}

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG) //Show logs at DEBUG level and higher
        .init();

    // load environment variables   
    dotenv().ok();

    // create database pool
    let config = Config::init();
    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("✅ Database pool created successfully.");
            pool
        }
        Err(e) => {
            println!("❌ Failed to create database pool: {:?}", e);
            std::process::exit(1);
        }
    };

    // CORS configuration
    let cors = CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap()) //Only requests from http://localhost:3000 are allowed
        .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT]) //Configure which headers the frontend can send:
        .allow_credentials(true)//Allows sending cookies or Authorization headers with requests. Required for authenticated requests
        .allow_methods([Method::GET, Method::POST, Method::PUT]); //Allowed HTTP methods

    let db_client = DBClient::new(pool);
    let app_state = AppState {
        env: config.clone(),
        db_client,
    };

    let app = Router::new()
        .layer(cors) // Add middleware (runs on every request)
        .with_state(app_state);

    println!("🚀 Server running at http://localhost:{}", config.port);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", &config.port))
        .await
        .expect("❌ Failed to bind to address");

    axum::serve(listener, app).await.unwrap();
}
