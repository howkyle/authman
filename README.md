# uman

User management for GO

# how to use

1. import "github.com/howkyle/uman"

# Usermanager

1.  implement required uman.UserRepository behaviors

    type UserDeleter interface {

        Delete(id interface{}) error

    }

    type UserCreator interface {

        Create(u User) (interface{}, error)

    }

    type UserRetriever interface {

        Retrieve(id interface{}) (User, error)

    }

    type UserManager interface {
    UserCreator
    UserRetriever
    UserDeleter
    }

2.  create new instance using approproate repository interface implentation, 'r'

    //r uman.UserCreator
    c:=uman.NewCreator(r)
    or
    //r uman.UserRetriever
    r:=uman.NewRetriever(r)
    or
    //r uman.UserDeleter
    d:=uman.NewDeleter(r)
    or
    //r uman.UserRepository
    um:=uman.NewUserManager(r)

# Authmanager

1.  implement behaviour of uman.User interface

    //specifies user behaviour
    type User interface {
    //returns the primary key id of the user
    GetID() interface{}
    //returns the username of the user
    GetUsername() string
    //returns the email address of a user
    GetEmail() string
    //returns the hashed password of a user
    GetPassword() string
    }

2.  create instance

    //secret - secret key used to sign token
    //authid - cookie name or header name where token is stored
    //issuer - issuer of auth eg localhost

    a := uman.NewJWTAuthManager(secret, authid, issuer)
