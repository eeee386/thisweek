-- name: AddTask :one
  INSERT INTO tasks(id, title, description, event_start, event_end, repetitions, user_id, tag_id, created_at, updated_at)
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
  RETURNING *;

-- name: GetTasksByUserId :many
  SELECT * FROM tasks WHERE user_id = $1;

-- name: UpdateTask :one
  UPDATE tasks
  SET title = $3,
      description = $4,
      event_start = $5,
      event_end = $6,
      repetitions = $7,
      tag_id = $8,
      updated_at =$9
  WHERE id = $1 AND user_id = $2
  RETURNING *;

-- name: DeleteTask :exec
  DELETE FROM tasks * WHERE id = $1 AND user_id = $2;
