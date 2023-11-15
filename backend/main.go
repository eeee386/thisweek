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
	"golang.org/x/crypto/sha3"
)

func sha3Hash(input string) string {

	// Create a new hash & write input string
	hash := sha3.New256()
	_, _ = hash.Write([]byte(input))

	// Get the resulting encoded byte slice
	sha3 := hash.Sum(nil)

	// Convert the encoded byte slice to a string
	return fmt.Sprintf("%x", sha3)
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	utils.RespondWithJSON(w, 200, struct {
		Status string `json:"status"`
	}{Status: "OK"})
}

func errorHandler(w http.ResponseWriter, r *http.Request) {
	utils.RespondWithError(w, 500, "Internal Server Error")
}

type apiConfig struct {
	DB  *database.Queries
	ctx context.Context
}

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

	}
}

func (a apiConfig) registerHandler(w http.ResponseWriter, r *http.Request) {
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

func (a apiConfig) mintToken(id string, issuer string, expiresInSeconds int) (string, error) {
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

func (a apiConfig) mintRefreshToken(id string) (string, error) {
	tokenString, err := a.mintToken(id, "thisweek-refresh", 5184000)
	if err == nil {
		godotenv.Load()
		refreshObject := database.AddRefreshTokenParams{}
		refreshObject.IssuedAt = time.Now()
		refreshObject.ID = sha3Hash(tokenString)
		a.DB.AddRefreshToken(a.ctx, refreshObject)
	}
	return tokenString, err
}

func (a apiConfig) mintAccessToken(id string) (string, error) {
	return a.mintToken(id, "thisweek-access", 86400)
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

func (a apiConfig) login(w http.ResponseWriter, r *http.Request) {
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

	v1Router.Post("/register", registerHandler)

	err := http.ListenAndServe(fmt.Sprintf(":%s", port), r)
	fmt.Println(err)
}
