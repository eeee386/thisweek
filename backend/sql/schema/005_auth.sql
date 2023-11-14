-- +goose Up
CREATE TABLE auth(
  id TEXT PRIMARY KEY
);

-- +goose Down
DROP TABLE auth;    
