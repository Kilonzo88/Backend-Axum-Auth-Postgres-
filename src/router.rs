use std::sync::Arc;
use axum::{middleware, Router};
use tower_http::trace::TraceLayer;
use crate::{handler::{auth::auth_handler, users::users_handler}, middleware::auth, AppState};

pub fn create_router(app_state: Arc<AppState>) -> Router {
    let api_route = Router::new()
        .nest("/auth", auth_handler())
        .nest(
            "/users",
            users_handler(app_state.clone())
                .layer(middleware::from_fn_with_state(app_state.clone(), auth))
        ); // Removed .layer(Extension(app_state));

    Router::new()
        .nest("/api", api_route)
        .with_state(app_state) // Set the app_state for the main router
        .layer(TraceLayer::new_for_http())
}
