package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"thisweek/backend/internal/auth"
	"thisweek/backend/internal/database"
	"thisweek/backend/internal/utils"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	utils.RespondWithJSON(w, 200, struct {
		Status string `json:"status"`
	}{Status: "OK"})
}

func errorHandler(w http.ResponseWriter, r *http.Request) {
	utils.RespondWithError(w, 500, "Internal Server Error")
}

type authedHandler func(*utils.DBConfig, http.ResponseWriter, *http.Request, *database.User)

func authenticate(a *utils.DBConfig, handler authedHandler) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		bearerToken := r.Header.Get("Authorization")
		user, err := auth.ValidateBearerToken(a, bearerToken)
		// Handle error with database
		if err != nil {
			utils.RespondWithError(w, 401, "Unauthorized")
		} else {
			handler(a, w, r, &user)
		}
	}
}

func registerHandler(a *utils.DBConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		registerReq := auth.RegisterReq{}
		if err := decoder.Decode(&registerReq); err != nil {
			utils.RespondWithError(w, 400, "Bad request")
			return
		}
		registerUserRes, err := auth.CreateNewUser(a, &registerReq)
		// check error if it is a database one (500) or client error (400)
		if err != nil {
			utils.RespondWithError(w, 400, "Bad request")
		} else {
			utils.RespondWithJSON(w, 200, registerUserRes)
		}
	}
}

type TokenOperationType struct {
	token string
}

func revokeTokens(a *utils.DBConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		refreshTokenObj := TokenOperationType{}
		if err := decoder.Decode(&refreshTokenObj); err != nil {
			utils.RespondWithError(w, 400, "Bad request")
			return
		}
		if derr := a.DB.RevokeRefreshToken(a.CTX, refreshTokenObj.token); derr != nil {
			// TODO: handle not found as not an error
			utils.RespondWithError(w, 500, "Internal Server Error")
			return
		}
		utils.RespondWithJSON(w, 200, "OK")
	}
}

func refreshAccessToken(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	decoder := json.NewDecoder(r.Body)
	refreshTokenObj := TokenOperationType{}
	if err := decoder.Decode(&refreshTokenObj); err != nil {
		utils.RespondWithError(w, 400, "Bad request")
		return
	}
	tokenString, derr := a.DB.GetRefreshToken(a.CTX, refreshTokenObj.token)
	if derr != nil {
		utils.RespondWithError(w, 404, "Not Found")
		return
	}

	claims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString.ID, &claims, func(token *jwt.Token) (interface{}, error) {
		jwtSecret := os.Getenv("JWT_SECRET")
		return []byte(jwtSecret), nil
	})
	if err != nil || !token.Valid || claims.Issuer != auth.RefreshTokenIssuer {
		utils.RespondWithError(w, 401, "Unauthorized")
		return
	}

	newAccessToken, terr := auth.MintAccessToken(a, user.ID.String())
	if terr != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return
	}
	newAccessTokenObj := TokenOperationType{
		token: newAccessToken,
	}
	utils.RespondWithJSON(w, 200, newAccessTokenObj)
	return
}

type AuthenticatedUser struct {
	database.User
	token string
}

func login(a *utils.DBConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		userReqParams := auth.LoginReqUser{}
		if err := decoder.Decode(&userReqParams); err != nil {
			utils.RespondWithError(w, 400, "Bad Request")
			return
		}
		resUser, err := auth.FromDBUserToLoginResUser(a, userReqParams)
		// Handle user or database error
		if err != nil {
			utils.RespondWithError(w, 401, "Unauthorized")
			return
		}
		utils.RespondWithJSON(w, 200, resUser)
	}
}

type GetTagsParams struct {
	UserId uuid.UUID `json:"user_id"`
}

func getTags(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	tags, err := a.DB.GetTagsByUserId(a.CTX, user.ID)
	if err != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return
	} else {
		utils.RespondWithJSON(w, 200, tags)
	}
}

type TagRequestType struct {
	Name string `json:"name"`
}

func renameTag(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	id := chi.URLParam(r, "id")
	decoder := json.NewDecoder(r.Body)
	renameBody := TagRequestType{}
	if err := decoder.Decode(&renameBody); err != nil {
		utils.RespondWithError(w, 400, "Bad Request")
		return
	}
	uuid, err := uuid.Parse(id)
	if err != nil {
		utils.RespondWithError(w, 400, "Bad Request")
		return
	}
	dbObj := database.RenameTagParams{
		ID:        uuid,
		Name:      renameBody.Name,
		UpdatedAt: time.Now(),
		UserID:    user.ID,
	}
	tag, err := a.DB.RenameTag(a.CTX, dbObj)
	// handle errors coming from not found, or database error
	if err != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return
	}
	utils.RespondWithJSON(w, 200, tag)
}

func deleteTag(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	idstring := chi.URLParam(r, "id")
	id, err := uuid.Parse(idstring)
	if err != nil {
		utils.RespondWithError(w, 400, "Bad Request")
		return
	}
	dbObj := database.DeleteTagParams{
		ID:     id,
		UserID: user.ID,
	}
	derr := a.DB.DeleteTag(a.CTX, dbObj)
	// handle not found, or database error
	if derr != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return
	}
	utils.RespondWithJSON(w, 200, "OK")
	return
}

func createTag(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	decoder := json.NewDecoder(r.Body)
	tagBody := TagRequestType{}
	if err := decoder.Decode(&tagBody); err != nil {
		utils.RespondWithError(w, 400, "Bad Request")
		return
	}
	timeStamp := time.Now()
	dbObj := database.AddTagParams{
		ID: uuid.New(),
		Name: tagBody.Name,
		UserID: user.ID,
		CreatedAt: timeStamp,
		UpdatedAt: timeStamp,
	}
	tag, err := a.DB.AddTag(a.CTX, dbObj)
	// handle not found or database error
  if err != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return
	}
	utils.RespondWithJSON(w, 200, tag)
}

func getTasks(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	tasks, err := a.DB.GetTasksByUserId(a.CTX, user.ID)
	if err != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return 
	}
	utils.RespondWithJSON(w, 200, tasks)
}

type TaskRequestType struct {
	Title string `json:"title"`
	Description string `json:"description"`
	EventStart string `json:"event_start"`
	EventEnd string `json:"event_end"`
	Repetitions string `json:"repetitions"`
	TagID string `json:"tag_id"`
}

func updateTasks(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	taskReqObj := TaskRequestType{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&taskReqObj); err != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return
	}
	eventStartTime, eserr := time.Parse(utils.BaseDateString, taskReqObj.EventStart)
	if eserr != nil {
		utils.RespondWithError(w, 400, "Event start is not a valid date!")
		return
	}
	eventEndTime, eeerr := time.Parse(utils.BaseDateString, taskReqObj.EventEnd)
	if eeerr != nil {
		utils.RespondWithError(w, 400, "Event end is not a valid date!")
		return
	}
  tagId, err:= uuid.Parse(taskReqObj.TagID)
	if err!= nil {
		utils.RespondWithError(w, 400, "Invalid Tag ID")
		return
	}
	updateTaskObj := database.UpdateTaskParams{
		ID: uuid.New(),
		UserID: user.ID,
		Title: taskReqObj.Title,
		EventStart: eventStartTime,
		EventEnd: eventEndTime,
		UpdatedAt: time.Now(),
		Repetitions: taskReqObj.Repetitions,
		TagID: tagId,
	}
	task, err := a.DB.UpdateTask(a.CTX, updateTaskObj)
	if err != nil {
		utils.RespondWithJSON(w, 500, "Internal Server Error")
		return
	}
	utils.RespondWithJSON(w, 200, task)
}

func createTask(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	taskReqObj := TaskRequestType{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&taskReqObj); err != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return
	}
	eventStartTime, eserr := time.Parse(utils.BaseDateString, taskReqObj.EventStart)
	if eserr != nil {
		utils.RespondWithError(w, 400, "Event start is not a valid date!")
		return
	}
	eventEndTime, eeerr := time.Parse(utils.BaseDateString, taskReqObj.EventEnd)
	if eeerr != nil {
		utils.RespondWithError(w, 400, "Event end is not a valid date!")
		return
	}
  tagId, err:= uuid.Parse(taskReqObj.TagID)
	if err!= nil {
		utils.RespondWithError(w, 400, "Invalid Tag ID")
		return
	}
	timeStamp := time.Now()
	addTaskObj := database.AddTaskParams{
		ID: uuid.New(),
		UserID: user.ID,
		Title: taskReqObj.Title,
		EventStart: eventStartTime,
		EventEnd: eventEndTime,
		UpdatedAt: timeStamp,
		CreatedAt: timeStamp,
		Repetitions: taskReqObj.Repetitions,
		TagID: tagId,
	}
	task, err := a.DB.AddTask(a.CTX, addTaskObj)
	if err != nil {
		utils.RespondWithJSON(w, 500, "Internal Server Error")
		return
	}
	utils.RespondWithJSON(w, 200, task)
}

func deleteTask(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	idstring := chi.URLParam(r, "id")
	id, err := uuid.Parse(idstring)
	if err != nil {
		utils.RespondWithError(w, 400, "Invalid id in param")
		return
	}
	derr := a.DB.DeleteTask(a.CTX, database.DeleteTaskParams{UserID: user.ID, ID: id})
	if derr != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return
	}
	utils.RespondWithJSON(w, 200, "OK")
}

func main() {
	godotenv.Load()
	port := os.Getenv("PORT")

	dbURL := os.Getenv("CONN")
	db, derr := sql.Open("postgres", dbURL)
	if derr != nil {
		fmt.Println(derr.Error())
		return
	}

	dbQueries := database.New(db)
	apiCfg := utils.DBConfig{}
	apiCfg.DB = dbQueries

	apiCfg.CTX = context.Background()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET, POST, OPTIONS, PUT, DELETE"},
		AllowedHeaders: []string{"*"},
	}))

	v1Router := chi.NewRouter()
	r.Mount("/v1", v1Router)

	v1Router.Get("/readiness", readinessHandler)
	v1Router.Get("/err", errorHandler)

	v1Router.Post("/register", registerHandler(&apiCfg))
	v1Router.Post("/login", login(&apiCfg))
	v1Router.Post("/revokeAccessToken", revokeTokens(&apiCfg))
	v1Router.Post("/refreshAccessToken", authenticate(&apiCfg, refreshAccessToken))

	v1Router.Get("/tags", authenticate(&apiCfg, getTags))
	v1Router.Put("/tags/{id}", authenticate(&apiCfg, renameTag))
	v1Router.Delete("/tags/{id}", authenticate(&apiCfg, deleteTag))
	v1Router.Post("/tags", authenticate(&apiCfg, createTag))

	v1Router.Get("/tasks", authenticate(&apiCfg, getTasks))
	v1Router.Put("/tasks/{id}", authenticate(&apiCfg, updateTasks))
	v1Router.Delete("/tags/{id}", authenticate(&apiCfg, deleteTask))
	v1Router.Post("/tags", authenticate(&apiCfg, createTask))

	err := http.ListenAndServe(fmt.Sprintf(":%s", port), r)
	fmt.Println(err)
}
