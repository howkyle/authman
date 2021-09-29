package uman

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type userPassCredentials struct {
	principal string
	password  string
}

//returns the credentials principal, username, user id etc
func (u userPassCredentials) Identity() string {
	return u.principal
}

//returns a string representaion of the hash of the stored password
func (u userPassCredentials) Hash() (string, error) {
	hash, err := bcryptHash(u.password)
	if err != nil {
		return "", fmt.Errorf("unable to hash password: %w", err)
	}
	return string(hash), nil
}

func (u userPassCredentials) Password() string {
	return u.password
}

//represent jwt authentication object
type jwtAuth struct {
	access_token string
}

//returns the jwt
func (j jwtAuth) Auth() string {
	return j.access_token
}

//represents jwt authentcation manager
type jwtAuthMan struct {
	secret string
	issuer string
}

//compares a users credentials to a given password
func (a jwtAuthMan) Authenticate(u Credentials, password string) (Authentication, error) {
	err := bcryptCompare([]byte(u.Password()), []byte(password))
	if err != nil {
		return jwtAuth{}, fmt.Errorf("credentials not equal: %w", err)
	}

	token, err := createToken(u.Identity(), a.secret, a.issuer)
	if err != nil {
		return nil, fmt.Errorf("token creation failed: %w", err)
	}
	return jwtAuth{token}, nil
}

func (a jwtAuthMan) Filter(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//check auth in requests
		cookie, err := r.Cookie("pyt")
		if err != nil {
			http.Error(w, "missing authentication", http.StatusUnauthorized)
			return
		}
		sub, err := verifyToken(cookie.Value, a.secret)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "sub", sub)

		h.ServeHTTP(w, r.WithContext(ctx))
	}
}

//creates a new instance of the jwt auth manager with a secret and issuer
func NewJWTAuth(secret string, issuer string) jwtAuthMan {
	return jwtAuthMan{secret: secret}
}

//helpers

//compares passwords using brypt
func bcryptCompare(a, b []byte) error {
	err := bcrypt.CompareHashAndPassword(a, b)
	if err != nil {
		return fmt.Errorf("password comparision failed: %v", err)
	}
	return nil
}

//creates jwt using subject and secret, returns signed string
func createToken(subject string, secret string, issuer string) (string, error) {
	claims := jwt.StandardClaims{
		Subject:   subject,
		ExpiresAt: time.Now().Add(time.Minute * 15).Unix(),
		Issuer:    issuer,
		IssuedAt:  time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ts, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("unable to sign token: %v", err)
	}
	return ts, nil
}

//takes a token string and the server secret and parses and validates token and returns
//the subject i.e username
func verifyToken(t string, secret string) (string, error) {
	//todo add more validations and checks
	token, err := jwt.ParseWithClaims(t, &jwt.StandardClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return "", fmt.Errorf("unable to parse token: %w", err)
	}
	c := token.Claims.(*jwt.StandardClaims)
	// uid, err := strconv.ParseUint(c.Subject, 10, 64)
	// if err != nil {
	// 	return 0, fmt.Errorf("unable to parse sub: %w", err)
	// }
	return c.Subject, nil
}

//hashes password using bcrypt
func bcryptHash(password string) ([]byte, error) {
	hp, err := bcrypt.GenerateFromPassword([]byte(password), 15)
	if err != nil {
		log.Printf("hash failed: %v", err)
		return nil, fmt.Errorf("unable to hash password: %v", err)
	}
	return hp, nil
}

//takes identifier and password and returns user pass credential struct
func NewUserPassCredentials(id string, password string) Credentials {
	u := userPassCredentials{principal: id, password: password}
	return u
}

func NewUPCredentials(id, password string) Credentials {
	return userPassCredentials{principal: id, password: password}
}
