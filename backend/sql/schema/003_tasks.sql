
-- +goose Up
CREATE TYPE repetition_types AS ENUM ('day', 'week', 'month', 'year');
  
CREATE TABLE tasks(
 id UUID PRIMARY KEY,
 title TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,
 updated_at TIMESTAMP NOT NULL,
 description TEXT NOT NULL,
 event_start TIMESTAMP NOT NULL,
 event_end TIMESTAMP NOT NULL,
 repetitions repetitions_type,
 user_id UUID NOT NULL,
 tag_id UUID NOT NULL,
 CONSTRAINT userID
 FOREIGN KEY(user_id) REFERENCES users(id)
 ON DELETE CASCADE,
 CONSTRAINT tagId
 FOREIGN KEY(tag_id) REFERENCES tags(id)
);

-- +goose Down
DROP TABLE users;
