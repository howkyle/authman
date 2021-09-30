package uman

import "net/http"

type MiddlewareFilter interface {
	// takes HandlerFunc h and returns a function which verifies user's access
	//using the auth related to authid and calls the passed function hon success
	Filter(h http.HandlerFunc) http.HandlerFunc
}

type Authenticator interface {
	//accepts user details and given password, compares equality and returns auth type
	Authenticate(u Credentials, password string) (Authentication, error)
}
type AuthManager interface {
	// //accepts username and password and transforms to custom user details type
	// NewCredentials(sub interface{}, password string) Credentials
	Authenticator
	MiddlewareFilter
}

type Authentication interface {
	//retrieves string details about authentication jwt, session etc
	Auth() string
}

//interface to represent user credentials
type Credentials interface {
	Password
	Identifier
}

type Identifier interface {
	//retrieves the principal associated with the credentials eg. username, id etc
	Identity() string
}

type Hasher interface {
	//returns a string representation of the hash of the stored password
	Hash() (string, error)
}
type Password interface {
	//returns the given password
	Password() string
	Hasher
}
