package main

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/login", Login)
	r.Route("/secured", func(r chi.Router) {
		r.Use(SecureEndpoints)
		r.Get("/", SecuredEndpoint)
	})
	r.Route("/unsecured", func(r chi.Router) {
		r.Get("/", UnSecuredEndpoint)
	})

	err := http.ListenAndServe(":5005", r)
	if err != nil {
		log.Fatal(err)
	}
}

func Login(writer http.ResponseWriter, request *http.Request) {
	// write some logic to check user

	// generate access token
	token, err := NewAccessToken(UserClaims{
		Id:    "1",
		First: "fname",
		Last:  "lname",
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Second * 24).Unix(),
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	writer.Write([]byte(token))
}

func SecuredEndpoint(writer http.ResponseWriter, request *http.Request) {
	writer.Write([]byte("ok"))
}

func UnSecuredEndpoint(writer http.ResponseWriter, request *http.Request) {
	writer.Write([]byte("ok"))
}

type UserClaims struct {
	Id    string `json:"id"`
	First string `json:"first"`
	Last  string `json:"last"`
	jwt.StandardClaims
}

func NewAccessToken(claims UserClaims) (string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return accessToken.SignedString([]byte("TOKEN_SECRET"))
}

func ParseAccessToken(accessToken string) (*UserClaims, error) {
	parsedAccessToken, err := jwt.ParseWithClaims(accessToken, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("TOKEN_SECRET"), nil
	})
	if err != nil {
		return nil, err
	}
	return parsedAccessToken.Claims.(*UserClaims), nil
}

func SecureEndpoints(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")

		// validate bearer token
		if validateBearerToken(token) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("StatusUnauthorized"))
			return
		}

		// remove Bearer from token
		token = token[7:]

		// extract claims from token
		userClaims, err := ParseAccessToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid token"))
			return
		}

		// check user by userClaims.Id
		log.Printf("userID: %s", userClaims.Id)

		next.ServeHTTP(w, r)
	})
}

func validateBearerToken(token string) bool {
	return token != "" && len(token) > 8 && strings.HasPrefix(token, "Bearer")
}
