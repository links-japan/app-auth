package auth

type Storage interface {
	GetUser(u *User) error
	UpsertUser(u *User) error
	UpdateUser(u *User, fields map[string]interface{}) error
}
