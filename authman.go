package authman

import "net/http"

type MiddlewareFilter interface {
	// takes HandlerFunc h and returns a function which verifies user's access
	//using the auth related to authid and calls the passed function hon success
	Filter(h http.HandlerFunc) http.HandlerFunc
}

type Authenticator interface {
	//accepts user details and given password, compares equality and returns auth type
	Authenticate(u Credential, password string) (Authentication, error)
}
type AuthManager interface {
	Authenticator
	MiddlewareFilter
}

type Authentication interface {
	//retrieves string details about authentication jwt, session etc
	AsString() string
	//returns auth stored in a net/http cookie
	AsCookie() http.Cookie
}
