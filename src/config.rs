#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_maxage: i64,
    pub port: u16,
}

impl Config {
    pub fn init() -> Config {
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let jwt_maxage = std::env::var("JWT_MAXAGE").expect("JWT_MAXAGE must be set");

        // Read the port from the "PORT" environment variable.
        // .ok() converts the Result (from var()) into an Option. If the var is not set, it's None.
        // .and_then(|s| s.parse().ok()) attempts to parse the string value into a u16.
        //    If the parsing fails (e.g., not a valid number), it also results in None.
        // .unwrap_or(8000) provides a default value of 8000 if the environment variable
        //    was not set or could not be parsed into a u16.
        let port = std::env::var("PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8000);

        Config {
            database_url,
            jwt_secret,
            jwt_maxage: jwt_maxage.parse().unwrap(),
            port,
        }
    }
}
