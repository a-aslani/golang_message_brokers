package event

const (
	UserCreated = "v1.user.created"
)

type UserCreatedData struct {
	ID        string
	FirstName string
	LastName  string
	Email     string
}
