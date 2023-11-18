-- +goose Up
  CREATE TABLE tags(
  id UUID PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  user_id UUID NOT NULL,
  CONSTRAINT userID
  FOREIGN KEY(user_id) REFERENCES users(id)
  ON DELETE CASCADE
);

-- +goose Down
DROP TABLE tags;
