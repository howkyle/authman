package uman

type UserDeleter interface {
	//takes and id and deletes the associated user, returns nil on success
	Delete(id uint) error
}

type UserCreator interface {
	//accepts an instance of user and returns the id of the created user
	Create(u User) (uint, error)
}

type UserRetriever interface {
	//takes a user id and returns a User
	Retrieve(id uint) (User, error)
}

type Emailer interface {
	//sends an email to a slice of recipients
	Send(body string, recipient []string) error
}

//handles user
type UserManager interface {
	UserCreator
	UserRetriever
	// Emailer
	UserDeleter
}

type UserRepository interface {
	UserCreator
	UserDeleter
	UserRetriever
}

//specifies user behaviour
type User interface {
	//returns the primary key id of the user
	GetID() uint
	//returns the email address of a user
	GetEmail() string
}
