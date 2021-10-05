package authman

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var FailedPasswordHash = errors.New("failed to hash password")
var FailedTokenCreation = errors.New("failed to create token")
var FailedCredentialMatch = errors.New("credential comparison failed")
var FailedPasswordCompare = errors.New("password comparison failed")
var FailedTokenSigning = errors.New("failed to sign token")
var FailedTokenParsing = errors.New("failed to parse token")
var MissingAuthentication = errors.New("authentication not found")

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
		return "", err
	}
	return string(hash), nil
}

func (u userPassCredentials) String() string {
	return u.password
}

//represent jwt authentication object
type auth struct {
	access_token string
	//issuer of authentication
	issuer string
	//cookie or header name where auth token is stored
	authid string
	//length of the session
	session_len time.Duration
}

//returns the jwt
func (a auth) AsString() string {
	return a.access_token
}

//returns http cookie with auth
func (a auth) AsCookie() http.Cookie {
	return http.Cookie{Name: a.authid, Value: a.access_token, Domain: a.issuer, Expires: time.Now().Add(a.session_len)}
}

//represents jwt authentcation manager
type jwtAuthMan struct {
	secret string
	auth   auth
}

//compares a users credentials to a given password
func (a jwtAuthMan) Authenticate(u Credential, password string) (Authentication, error) {
	err := bcryptCompare([]byte(u.String()), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", FailedCredentialMatch, err)
	}

	a.auth.access_token, err = createToken(u.Identity(), a.secret, a.auth.issuer, a.auth.session_len)
	if err != nil {
		return nil, fmt.Errorf("%w:%v", FailedTokenCreation, err)
	}
	return a.auth, nil
}

//finds a cookie with the named authid and validates auth stored in cookie,
// serves the passed function
func (a jwtAuthMan) Filter(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//check auth in requests
		cookie, err := r.Cookie(a.auth.authid)
		if err != nil {
			http.Error(w, MissingAuthentication.Error(), http.StatusUnauthorized)
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

//creates a new instance of the jwt auth manager with a secret and issuer and session duration
func NewJWTAuthManager(secret string, authid, issuer string, session_len time.Duration) AuthManager {
	return jwtAuthMan{secret: secret, auth: auth{issuer: issuer, authid: authid, session_len: session_len}}
}

//helpers

//compares passwords using brypt
func bcryptCompare(a, b []byte) error {
	err := bcrypt.CompareHashAndPassword(a, b)
	if err != nil {
		return fmt.Errorf("%w: %v", FailedPasswordCompare, err)
	}
	return nil
}

//creates jwt using subject and secret, returns signed string
func createToken(subject string, secret string, issuer string, session_len time.Duration) (string, error) {
	claims := jwt.StandardClaims{
		Subject:   subject,
		ExpiresAt: time.Now().Add(session_len).Unix(),
		Issuer:    issuer,
		IssuedAt:  time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ts, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("%w: %v", FailedTokenSigning, err)
	}
	return ts, nil
}

//takes a token string and the server secret and parses and validates token and returns
//the subject i.e username, user id
func verifyToken(t string, secret string) (string, error) {
	//todo add more validations and checks
	token, err := jwt.ParseWithClaims(t, &jwt.StandardClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", FailedTokenParsing, err)
	}
	c := token.Claims.(*jwt.StandardClaims)
	return c.Subject, nil
}

//hashes password using bcrypt
func bcryptHash(password string) ([]byte, error) {
	hp, err := bcrypt.GenerateFromPassword([]byte(password), 15)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", FailedPasswordHash, err)
	}
	return hp, nil
}

//takes identifier and password and returns user pass credential struct
func NewUserPassCredentials(id string, password string) Credential {
	u := userPassCredentials{principal: id, password: password}
	return u
}
