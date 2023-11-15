-- +goose Up
CREATE TABLE auth(
  id TEXT PRIMARY KEY,
  issued_at TIMESTAMP NOT NULL
);

-- +goose Down
DROP TABLE auth;    
