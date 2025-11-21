-- Add down migration script here
DROP TABLE IF EXISTS "users";
DROP TABLE IF EXISTS user_roles;
DROP EXTENSION IF EXISTS "uuid-ossp";