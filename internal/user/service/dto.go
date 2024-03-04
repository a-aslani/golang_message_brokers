package service

type LoginDTO struct {
	Email, Password string
}

type RegisterDTO struct {
	FirstName, LastName, Email, Password string
}

type GetUserDTO struct {
	UserID string
}
