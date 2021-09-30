//basic user management
package uman

type UserDeleter interface {
	//takes and id and deletes the associated user, returns nil on success
	Delete(id interface{}) error
}

type UserCreator interface {
	//accepts an instance of user and returns the representation of the created user
	Create(u User) (interface{}, error)
}

type UserRetriever interface {
	//takes a user id and returns a User
	Retrieve(id interface{}) (User, error)
}

type Emailer interface {
	//sends an email to a slice of recipients
	Send(body string, recipient []string) error
}

//specifies behaviour of user
type UserManager interface {
	UserCreator
	UserRetriever
	// Emailer
	UserDeleter
}

//specifes behavior of user repository
type UserRepository interface {
	UserCreator
	UserDeleter
	UserRetriever
}

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
