package auth

import (
	"fmt"
	"os"
	"strings"
	"thisweek/backend/internal/database"
	"thisweek/backend/internal/utils"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

const AccessTokenIssuer = "thisweek-access"
const RefreshTokenIssuer = "thisweek-refresh"

func mintToken(a *utils.DBConfig, id string, issuer string, expiresInSeconds int) (string, error) {
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

func MintRefreshToken(a *utils.DBConfig, id string) (string, error) {
	tokenString, err := mintToken(a, id, RefreshTokenIssuer, 5184000)
	if err == nil {
		godotenv.Load()
		refreshObject := database.AddRefreshTokenParams{}
		refreshObject.IssuedAt = time.Now()
		refreshObject.ID = tokenString
		a.DB.AddRefreshToken(a.CTX, refreshObject)
	}
	return tokenString, err
}

func MintAccessToken(a *utils.DBConfig, id string) (string, error) {
	return mintToken(a, id, "thisweek-access", 86400)
}

func ValidateBearerToken(a *utils.DBConfig, bearerToken string) (database.User, error) {
	jwtToken := strings.Split(bearerToken, " ")[1]
	claims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(jwtToken, &claims, func(token *jwt.Token) (interface{}, error) {
		jwtSecret := os.Getenv("JWT_SECRET")
		return []byte(jwtSecret), nil
	})
	if err == nil && token.Valid && claims.Issuer == AccessTokenIssuer {
		if userId, perr := uuid.Parse(claims.Subject); perr != nil {
			return a.DB.GetUserById(a.CTX, userId)
		}
	}
	return database.User{}, fmt.Errorf("Invalid Token")
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

func FromDBUserToLoginResUser(a *utils.DBConfig, userReqParams LoginReqUser) (LoginResUser, error) {
	user, err := a.DB.GetUserByEmail(a.CTX, userReqParams.Email)
	// Handle Not found or other error differently 
	if err != nil {
		return LoginResUser{}, nil
	}
	if perr := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userReqParams.Password)); perr != nil {
		return LoginResUser{}, perr
	} 
	token, terr := MintAccessToken(a, user.ID.String())
	if terr != nil {
		return LoginResUser{}, terr
	}
	refreshToken, cerr := MintRefreshToken(a, user.ID.String())
	if cerr != nil {
		return LoginResUser{}, cerr
	}
	resUser := LoginResUser{}
	resUser.AccessToken = token
	resUser.CreatedAt = user.CreatedAt
	resUser.UpdatedAt = user.UpdatedAt
	resUser.Email = user.Email
	resUser.ID = user.ID
	resUser.RefreshToken = refreshToken
	return resUser, nil
}


type RegisterReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRes struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func CreateNewUser(a *utils.DBConfig, registerReq *RegisterReq) (RegisterRes, error) {
	createUserObject := database.CreateUserParams{}
	createUserObject.Email = registerReq.Email
	createUserObject.Password = registerReq.Password
	timestamp := time.Now()
	createUserObject.CreatedAt = timestamp
	createUserObject.UpdatedAt = timestamp
	pass, perr := bcrypt.GenerateFromPassword([]byte(createUserObject.Password), 8)
	createUserObject.Password = fmt.Sprintf("%x", pass)
	if perr != nil {
		return RegisterRes{}, nil
	}
	user, err := a.DB.CreateUser(a.CTX, createUserObject)
	if err != nil {
		return RegisterRes{}, err
	}
	registerUserRes := RegisterRes{
		ID:        user.ID.String(),
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	return registerUserRes, nil
}
