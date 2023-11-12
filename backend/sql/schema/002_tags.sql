-- +goose Up
  CREATE TABLE tags(
  id UUID PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TIMESTAMP NOT NULL,
  updated_AT TIMESTAMP NOT NULL,
  CONSTRAINT userID
  FOREIGN KEY(user_id) REFERENCES users(id)
  ON DELETE CASCADE,
);

-- +goose Down
DROP TABLE tags;      
