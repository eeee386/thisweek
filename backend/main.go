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

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
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


func renameTag(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	id := chi.URLParam(r, "id")
	decoder := json.NewDecoder(r.Body)
	renameBody := utils.TagRequestType{}
	if err := decoder.Decode(&renameBody); err != nil {
		utils.RespondWithError(w, 400, "Bad Request")
		return
	}
	dbObj, err := renameBody.ToRenameTag(id, user.ID)
	if err != nil {
		utils.RespondWithError(w, 400, "Bad Request")
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
	tagBody := utils.TagRequestType{}
	if err := decoder.Decode(&tagBody); err != nil {
		utils.RespondWithError(w, 400, "Bad Request")
		return
	}
	dbObj := tagBody.ToCreateTag(user.ID)
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


func updateTasks(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	idstring := chi.URLParam(r, "id")
	taskReqObj := utils.TaskRequestType{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&taskReqObj); err != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return
	}
	updateTaskObj, err := taskReqObj.ToUpdateTask(idstring, user.ID)
	if err != nil {
		utils.RespondWithError(w, 400, err.Error())
	}
	task, err := a.DB.UpdateTask(a.CTX, updateTaskObj)
	if err != nil {
		utils.RespondWithJSON(w, 500, "Internal Server Error")
		return
	}
	utils.RespondWithJSON(w, 200, task)
}


func createTask(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	taskReqObj := utils.TaskRequestType{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&taskReqObj); err != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return
	}
	addTaskObj, err := taskReqObj.ToCreateTask(user.ID)
	if err != nil {
		utils.RespondWithError(w, 400, err.Error())
		return
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

func getDailyTasks(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	dailyTasks, err := a.DB.GetDailyTasksByUserId(a.CTX, user.ID)
	if err != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return
	}
	utils.RespondWithJSON(w, 200, dailyTasks)
}

func updateDailyTasks(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	idstring := chi.URLParam(r, "id")
	dailyTaskReqObj := utils.DailyTaskRequestType{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&dailyTaskReqObj); err != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return
	}
	updateTaskObj, err := dailyTaskReqObj.ToUpdateDailyTask(idstring, user.ID)
	if err != nil {
		utils.RespondWithError(w, 400, err.Error())
	}
	dailyTask, err := a.DB.UpdateDailyTask(a.CTX, updateTaskObj)
	if err != nil {
		utils.RespondWithJSON(w, 500, "Internal Server Error")
		return
	}
	utils.RespondWithJSON(w, 200, dailyTask)
}


func createDailyTask(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	taskReqObj := utils.DailyTaskRequestType{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&taskReqObj); err != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return
	}
	addTaskObj, err := taskReqObj.ToCreateDailyTask(user.ID)
	if err != nil {
		utils.RespondWithJSON(w, 400, err.Error())
	}
	task, err := a.DB.AddDailyTask(a.CTX, addTaskObj)
	if err != nil {
		utils.RespondWithJSON(w, 500, "Internal Server Error")
		return
	}
	utils.RespondWithJSON(w, 200, task)
}

func deleteDailyTask(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user *database.User) {
	idstring := chi.URLParam(r, "id")
	id, err := uuid.Parse(idstring)
	if err != nil {
		utils.RespondWithError(w, 400, "Invalid id in param")
		return
	}
	derr := a.DB.DeleteDailyTask(a.CTX, database.DeleteDailyTaskParams{UserID: user.ID, ID: id})
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
	v1Router.Delete("/tasks/{id}", authenticate(&apiCfg, deleteTask))
	v1Router.Post("/tasks", authenticate(&apiCfg, createTask))

	v1Router.Get("/dailytasks", authenticate(&apiCfg, getDailyTasks))
	v1Router.Put("/dailytasks/{id}", authenticate(&apiCfg, updateDailyTasks))
	v1Router.Delete("/dailytasks/{id}", authenticate(&apiCfg, deleteDailyTask))
	v1Router.Post("/dailytasks", authenticate(&apiCfg, createDailyTask))

	err := http.ListenAndServe(fmt.Sprintf(":%s", port), r)
	fmt.Println(err)
}
