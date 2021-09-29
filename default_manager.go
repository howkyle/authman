package uman

import "fmt"

type defaultCreator struct {
	repo UserCreator
}

func (um defaultCreator) Create(u User) (interface{}, error) {
	id, err := um.repo.Create(u)
	if err != nil {
		return 0, fmt.Errorf("unable to create user: %w", err)
	}
	return id, nil
}

type defaultRetriever struct {
	repo UserRetriever
}

func (um defaultRetriever) Retrieve(id interface{}) (User, error) {
	u, err := um.repo.Retrieve(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user from db: %w", err)
	}
	return u, nil
}

type defaultDeleter struct {
	repo UserDeleter
}

func (d defaultDeleter) Delete(id interface{}) error {
	err := d.repo.Delete(id)
	if err != nil {
		return fmt.Errorf("failed to delete user from db: %w", err)
	}
	return nil
}

//default user manager type
type defaultManager struct {
	repo UserRepository
}

func (um defaultManager) Create(u User) (interface{}, error) {
	id, err := um.repo.Create(u)
	if err != nil {
		return 0, fmt.Errorf("unable to create user: %w", err)
	}
	return id, nil
}

func (d defaultManager) Delete(id interface{}) error {
	err := d.repo.Delete(id)
	if err != nil {
		return fmt.Errorf("failed to delete user from db: %w", err)
	}
	return nil
}

func (um defaultManager) Retrieve(id interface{}) (User, error) {
	u, err := um.repo.Retrieve(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user from db: %w", err)
	}
	return u, nil
}

//creates a new creator passing a repository interface
func NewCreator(repo UserCreator) UserCreator {
	return defaultCreator{repo: repo}
}

//returns the default deleter created with the passed UserDeleter repo
func NewDeleter(repo UserDeleter) UserDeleter {
	return defaultDeleter{repo: repo}
}

//returns the default retriever created with the passed UserRetriever repo
func NewRetriever(repo UserRetriever) UserRetriever {
	return defaultRetriever{repo: repo}
}

// func newCreatorRetriever(repo Cre)

//creates a new instance of the user manager with the provided user repository
func NewUserManager(r UserRepository) UserManager {

	return defaultManager{repo: r}
}
