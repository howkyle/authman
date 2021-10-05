package authman

//interface to represent user credentials
type Credential interface {
	Password //todo maybe rename to something more appropriate/general
	Identifier
}

type Identifier interface {
	//retrieves the principal associated with the credentials eg. username, id etc
	Identity() string
}

type Password interface {
	//returns the given password
	String() string
	Hasher
}

type Hasher interface {
	//returns a string representation of the hash of the stored password
	Hash() (string, error)
}
