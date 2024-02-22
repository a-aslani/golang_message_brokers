package restapi

type RegisterRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name" validate:"required"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=5"`
}
