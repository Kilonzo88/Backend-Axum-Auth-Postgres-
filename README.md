# Axum Auth Backend with PostgreSQL

A production-ready Rust backend template built with Axum, featuring custom authentication, PostgreSQL integration, and email capabilities. This project serves as a comprehensive starting point for building secure, scalable web applications.

## Purpose

This repository is designed to be a **production-grade template** for developers who need:
- A robust authentication system with JWT tokens
- PostgreSQL database integration with migrations
- Email verification and password reset functionality
- A clean, maintainable project structure
- Industry best practices and security patterns

**Use this as your starting point** when building Axum applications that require authentication and database persistence.

---

## Features

### Authentication & Security
- **Custom JWT Authentication** - Secure token-based auth with refresh tokens
- **Password Hashing** - Argon2 password hashing
- **Email Verification** - User account verification via email
- **Password Reset** - Secure password recovery flow
- **Role-Based Access Control** - Flexible user permission system
- **Session Management** - Secure session handling

### Database
- **PostgreSQL Integration** - Production-ready database setup
- **SQLx** - Compile-time checked SQL queries
- **Database Migrations** - Version-controlled schema management
- **Connection Pooling** - Efficient database connections

### Email System
- **Email Service Integration** - SMTP email sending
- **Email Templates** - HTML email templates
- **Verification Emails** - Account verification workflow
- **Password Reset Emails** - Secure reset token delivery

### Architecture
- **Clean Code Structure** - Modular, maintainable organization
- **Error Handling** - Comprehensive error types and handling
- **Middleware** - Authentication and logging middleware
- **Environment Configuration** - .env based configuration

---

## Tech Stack

**Core Technologies:**
- **Axum** - High-performance web framework
- **PostgreSQL** - Relational database
- **SQLx** - Async SQL toolkit with compile-time verification
- **Tokio** - Async runtime
- **JWT (jsonwebtoken)** - Token-based authentication
- **Argon2** - Password hashing
- **Lettre** - Email sending
- **Serde** - Serialization/deserialization
- **Tower** - Middleware and services
- **Validator** - Request validation

---

## Prerequisites

- **Rust** (1.70 or later) - [Install Rust](https://rustup.rs/)
- **PostgreSQL** (14 or later) - [Install PostgreSQL](https://www.postgresql.org/download/)
- **SQLx CLI** - For database migrations
  ```bash
  cargo install sqlx-cli --no-default-features --features postgres
  ```

---

## Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Kilonzo88/Backend-Axum-Auth-Postgres-.git
cd Backend-Axum-Auth-Postgres-
```

### 2. Set Up Environment Variables
Create a `.env` file in the project root:

```env
# Database
DATABASE_URL=postgresql://username:password@localhost:5432/your_database

# Server
HOST=127.0.0.1
PORT=8000

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRATION=3600  # 1 hour in seconds
REFRESH_TOKEN_EXPIRATION=604800  # 7 days in seconds

# Email Configuration (SMTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=noreply@yourdomain.com

# Application
APP_NAME=Axum Auth Backend
APP_URL=http://localhost:8000
FRONTEND_URL=http://localhost:3000

# Security
BCRYPT_COST=12
```

### 3. Create the Database
```bash
# Create database
createdb your_database

# Or using psql
psql -U postgres
CREATE DATABASE your_database;
\q
```

### 4. Run Database Migrations
```bash
sqlx database create
sqlx migrate run
```

### 5. Build and Run
```bash
# Development mode
cargo run

# Production build
cargo build --release
./target/release/backend-axum-auth-postgres
```

The server will start at `http://localhost:8000`

---

## Project Structure

```
Backend-Axum-Auth-Postgres/
├── src/
│   ├── main.rs                 # Application entry point
│   ├── config/
│   │   └── mod.rs              # Configuration management
│   ├── models/
│   │   ├── mod.rs
│   │   ├── user.rs             # User model
│   │   └── token.rs            # Token models
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── auth.rs             # Authentication handlers
│   │   └── user.rs             # User management handlers
│   ├── middleware/
│   │   ├── mod.rs
│   │   ├── auth.rs             # JWT authentication middleware
│   │   └── logging.rs          # Request logging
│   ├── services/
│   │   ├── mod.rs
│   │   ├── auth_service.rs     # Auth business logic
│   │   ├── email_service.rs    # Email sending
│   │   └── user_service.rs     # User operations
│   ├── database/
│   │   ├── mod.rs
│   │   └── pool.rs             # Database connection pool
│   ├── utils/
│   │   ├── mod.rs
│   │   ├── jwt.rs              # JWT utilities
│   │   ├── password.rs         # Password hashing
│   │   └── validation.rs       # Input validation
│   ├── errors/
│   │   └── mod.rs              # Error types and handling
│   └── routes/
│       └── mod.rs              # Route definitions
├── migrations/                 # Database migrations
├── tests/                      # Integration tests
├── .env.example               # Environment variables template
├── Cargo.toml                 # Dependencies
└── README.md
```

---

## API Endpoints

### Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/auth/register` | Register new user | ❌ |
| `POST` | `/api/auth/login` | Login user | ❌ |
| `POST` | `/api/auth/refresh` | Refresh access token | ❌ |
| `POST` | `/api/auth/logout` | Logout user | ✅ |
| `GET` | `/api/auth/verify/:token` | Verify email | ❌ |
| `POST` | `/api/auth/forgot-password` | Request password reset | ❌ |
| `POST` | `/api/auth/reset-password/:token` | Reset password | ❌ |

### User Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/users/me` | Get current user | ✅ |
| `PUT` | `/api/users/me` | Update current user | ✅ |
| `DELETE` | `/api/users/me` | Delete current user | ✅ |
| `PATCH` | `/api/users/me/password` | Change password | ✅ |

### Health Check

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/health` | Service health status | ❌ |

---

## Usage Examples

### Register a New User
```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "johndoe",
    "password": "SecurePassword123!",
    "full_name": "John Doe"
  }'
```

**Response:**
```json
{
  "success": true,
  "message": "Registration successful. Please check your email to verify your account.",
  "user_id": "uuid-here"
}
```

### Login
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "username": "johndoe",
    "full_name": "John Doe",
    "is_verified": true
  }
}
```

### Get Current User (Protected Route)
```bash
curl -X GET http://localhost:8000/api/users/me \
  -H "Authorization: Bearer your-jwt-token"
```

---

## Security Best Practices

This template implements several security best practices:

1. **Password Security**
   - Argon2 hashing algorithm
   - Configurable cost factor
   - No plain-text password storage

2. **Token Security**
   - Short-lived access tokens (1 hour)
   - Long-lived refresh tokens (7 days)
   - Token rotation on refresh
   - Secure token storage

3. **Input Validation**
   - Email format validation
   - Password strength requirements
   - SQL injection prevention (SQLx compile-time checks)
   - XSS protection

4. **HTTPS Ready**
   - Configure reverse proxy (nginx/caddy) for production
   - Secure headers middleware

5. **Rate Limiting** (Recommended)
   - Add rate limiting middleware for production
   - Protect against brute force attacks

---

## Testing

```bash
# Run all tests
cargo test

# Run specific test module
cargo test auth

# Run with output
cargo test -- --nocapture
```

---

## Contributing

Contributions are welcome! This is a template project meant to help the community.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**Development Guidelines:**
- Follow Rust naming conventions
- Write tests for new features
- Update documentation
- Run `cargo fmt` and `cargo clippy` before committing

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [Axum](https://github.com/tokio-rs/axum) - The amazing web framework
- [SQLx](https://github.com/launchbadge/sqlx) - For compile-time SQL verification
- The Rust community for excellent crates and support

---

## Support

- **Issues**: [GitHub Issues](https://github.com/Kilonzo88/Backend-Axum-Auth-Postgres-/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Kilonzo88/Backend-Axum-Auth-Postgres-/discussions)

---

**Built with ❤️ using Rust**
