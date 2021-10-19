# authman

basic auth management for GO

# Usage

1. importing
   import "github.com/howkyle/authman"

2. creating an instance

   //secret - secret key used to sign token
   //authid - cookie name or header name where token is stored
   //issuer - issuer of auth eg localhost
   //session_exp - duration of the session (time.Duration)

   a := authman.NewJWTAuthManager(secret, authid, issuer, session_exp)

3. creating new credentials

   //principal - user id or username as a string
   //password - password input from user

   cred:=authman.NewUserPassCredentials(principal, password)

4. getting hashed password from new credentials

   pass, err:= cred.Hash()

5. authenticating a user

   //using an instance of authmanager

   a := authman.NewJWTAuthManager(secret, authid, issuer, session_exp)

   //retrieve the user and create new credentials

   cred:=authman.NewUserPassCredentials(principal, password)

   //take the credentials created from the retrieved user as authman.Credentials and takes takes the password to be validated.
   //returns an authman.Authentication instance or an error if authentication fails

   auth, err:= a.Authenticate(cred authman.Credentials, password string)

   //get auth as string type
   s:=auth.AsString()

   //get created auth as a net/http cookie
   c:=auth.AsCookie()

6. Filter Middleware
   //using an instance of authmanager

   a := authman.NewJWTAuthManager(secret, authid, issuer, session_exp)

   //wrap handler func with auth filter

   http.HandleFunc("/", a.Filter(func(w http.ResponseWriter, r \*http.Request){}))

   //filter checks the http request for the cookie storing the access token, verifies the token, extracts the principal, passes it to the request context with the key 'sub' and serves the wrapped HandlerFunc

   //if the token is invalid or the cookie isnt present, Filter returns a 401
