-- name: GetTagsByUserId :many
  SELECT * FROM tags WHERE user_id = $1;
  
-- name: AddTag :one
  INSERT INTO tags(id, name, user_id, created_at, updated_at)
  VALUES ($1, $2, $3, $4, $5)
  RETURNING *;

-- name: RenameTag :one
  UPDATE tags
   SET name = $3,
       updated_at = $4
  WHERE id = $1 AND user_id = $2
  RETURNING *;

-- name: DeleteTag :exec
  DELETE FROM tags WHERE id = $1 AND user_id = $2;
  
