
-- +goose Up
CREATE TABLE users(
 id UUID PRIMARY KEY,
 created_at TIMESTAMP NOT NULL,
 updated_at TIMESTAMP NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL   
);

CREATE INDEX email_index ON users USING HASH (email);

-- +goose Down
DROP TABLE users;
