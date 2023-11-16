package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"thisweek/backend/internal/database"
	"thisweek/backend/internal/utils"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	utils.RespondWithJSON(w, 200, struct {
		Status string `json:"status"`
	}{Status: "OK"})
}

func errorHandler(w http.ResponseWriter, r *http.Request) {
	utils.RespondWithError(w, 500, "Internal Server Error")
}

// If no change will happen on this -> make a DB wrapper out of this
// If a change were to happen break the db related sutff to a different struct
// I don't auth to depend on server api config
type apiConfig struct {
	DB  *database.Queries
	ctx context.Context
}

const AccessTokenIssuer = "thisweek-access"
const RefreshTokenIssuer = "thisweek-refresh"

type authedHandler func(http.ResponseWriter, *http.Request, database.User)


func (a *apiConfig) authenticate(handler authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearerToken := r.Header.Get("Authorization")
		jwtToken := strings.Split(bearerToken, " ")[1]
		claims := jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(jwtToken, &claims, func(token *jwt.Token) (interface{}, error) {
			jwtSecret := os.Getenv("JWT_SECRET")
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid || claims.Issuer != AccessTokenIssuer {
			utils.RespondWithError(w, 401, "Unauthorized")
			return
		}
		userId, perr := uuid.Parse(claims.Subject)
		if perr != nil {
			utils.RespondWithError(w, 401, "Unauthorized")
			return
		}
		user, derr := a.DB.GetUserById(a.ctx, userId)
		if derr != nil {
			utils.RespondWithError(w, 401, "Unauthorized")
			return
		}
		handler(w, r, user)
	}
}

func (a *apiConfig) registerHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	createUserObject := database.CreateUserParams{}
	if err := decoder.Decode(&createUserObject); err != nil {
		utils.RespondWithError(w, 400, "Bad request")
		return
	}
	timestamp := time.Now()
	createUserObject.CreatedAt = timestamp
	createUserObject.UpdatedAt = timestamp
	pass, perr := bcrypt.GenerateFromPassword([]byte(createUserObject.Password), 8)
	createUserObject.Password = fmt.Sprintf("%x", pass)
	if perr != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
	}
	user, err := a.DB.CreateUser(a.ctx, createUserObject)
	// check error if it is a database one (500) or client error (400)
	if err != nil {
		utils.RespondWithError(w, 400, "Bad request")
	} else {
		utils.RespondWithJSON(w, 200, user)
	}
}

func (a *apiConfig) mintToken(id string, issuer string, expiresInSeconds int) (string, error) {
	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
	claims := jwt.RegisteredClaims{}
	claims.Issuer = issuer
	claims.IssuedAt = jwt.NewNumericDate(time.Now().UTC())
	claims.ExpiresAt = jwt.NewNumericDate(claims.IssuedAt.Add(time.Second * time.Duration(expiresInSeconds)))
	claims.Subject = id
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func (a *apiConfig) mintRefreshToken(id string) (string, error) {
	tokenString, err := a.mintToken(id, RefreshTokenIssuer, 5184000)
	if err == nil {
		godotenv.Load()
		refreshObject := database.AddRefreshTokenParams{}
		refreshObject.IssuedAt = time.Now()
		refreshObject.ID = tokenString
		a.DB.AddRefreshToken(a.ctx, refreshObject)
	}
	return tokenString, err
}

func (a *apiConfig) mintAccessToken(id string) (string, error) {
	return a.mintToken(id, "thisweek-access", 86400)
}

type TokenOperationType struct {
	token string
}

func (a *apiConfig) revokeTokens(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		refreshTokenObj := TokenOperationType{}
		if err := decoder.Decode(&refreshTokenObj); err != nil {
			utils.RespondWithError(w, 400, "Bad request")
			return
		}
		derr := a.DB.RevokeRefreshToken(a.ctx, refreshTokenObj.token)
		// TODO: handle not found as not an error
		if derr != nil {
			utils.RespondWithError(w, 500, "Internal Server Error")
			return
		}
		utils.RespondWithJSON(w, 200, "OK")
	}
}

func (a *apiConfig) refreshAccessToken(w http.ResponseWriter, r *http.Request, user database.User) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		refreshTokenObj := TokenOperationType{}
		if err := decoder.Decode(&refreshTokenObj); err != nil {
			utils.RespondWithError(w, 400, "Bad request")
			return
		}
		tokenString, derr := a.DB.GetRefreshToken(a.ctx, refreshTokenObj.token)
		if derr != nil {
			utils.RespondWithError(w, 404, "Not Found")
			return
		}
		
		claims := jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(tokenString.ID, &claims, func(token *jwt.Token) (interface{}, error) {
			jwtSecret := os.Getenv("JWT_SECRET")
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid || claims.Issuer != AccessTokenIssuer {
			utils.RespondWithError(w, 401, "Unauthorized")
			return
		}
		
		newAccessToken, terr := a.mintAccessToken(user.ID.String())
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
}

type AuthenticatedUser struct {
	database.User
	token string
}

type LoginReqUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResUser struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
}

func (a *apiConfig) login(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	userReqParams := LoginReqUser{}
	if err := decoder.Decode(&userReqParams); err != nil {
		utils.RespondWithError(w, 400, "Bad Request")
		return
	}
	user, err := a.DB.GetUserByEmail(a.ctx, userReqParams.Email)
	resUser := LoginResUser{}
	token, terr := a.mintAccessToken(user.ID.String())
	if terr != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
		return
	}
	refreshToken, cerr := a.mintRefreshToken(user.ID.String())
	if cerr != nil {
		utils.RespondWithError(w, 500, "Internal Server Error")
	}
	resUser.AccessToken = token
	resUser.CreatedAt = user.CreatedAt
	resUser.UpdatedAt = user.UpdatedAt
	resUser.Email = user.Email
	resUser.ID = user.ID
	resUser.RefreshToken = refreshToken
	// Handle user or database error
	if err != nil {
		utils.RespondWithError(w, 401, "Unauthorized")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userReqParams.Password)) == nil {
		utils.RespondWithJSON(w, 200, user)
	}
	utils.RespondWithJSON(w, 200, user)
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
	apiCfg := apiConfig{}
	apiCfg.DB = dbQueries

	apiCfg.ctx = context.Background()

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

	v1Router.Post("/register", apiCfg.registerHandler)

	err := http.ListenAndServe(fmt.Sprintf(":%s", port), r)
	fmt.Println(err)
}
