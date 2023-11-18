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

type authedHandler func(*utils.DBConfig, http.ResponseWriter, *http.Request, database.User)

func authenticate(a *utils.DBConfig, handler authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearerToken := r.Header.Get("Authorization")
		user, err := auth.ValidateBearerToken(a, bearerToken)
		// Handle error with database
		if err != nil {
			utils.RespondWithError(w, 401, "Unauthorized")
		} else {
			handler(a, w, r, user)
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

func refreshAccessToken(a *utils.DBConfig, w http.ResponseWriter, r *http.Request, user database.User) {
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

	err := http.ListenAndServe(fmt.Sprintf(":%s", port), r)
	fmt.Println(err)
}
