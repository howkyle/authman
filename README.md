# uman

basic auth management for GO

# how to use

1. import "github.com/howkyle/auth"

# Authmanager

1.  create instance

    //secret - secret key used to sign token
    //authid - cookie name or header name where token is stored
    //issuer - issuer of auth eg localhost
    //session_exp - duration of the session (time.Duration)

    a := uman.NewJWTAuthManager(secret, authid, issuer, session_exp)
