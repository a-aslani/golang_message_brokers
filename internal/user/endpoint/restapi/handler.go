package restapi

import (
	"context"
	"github.com/a-aslani/golang_message_brokers/configs"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/framework"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/framework/model/payload"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/framework/util"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/logger"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/token"
	"github.com/a-aslani/golang_message_brokers/internal/user/service"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"net/http"
	"time"
)

type handler struct {
	framework.ControllerStarter
	userService     service.UserService
	log             logger.Logger
	jwt             token.JWT
	cfg             *configs.Config
	tokenMiddleware token.GinMiddleware
}

func NewHandler(appData framework.ApplicationData, log logger.Logger, jwt token.JWT, cfg *configs.Config, userService service.UserService) *handler {
	router := gin.Default()

	address := cfg.Servers[appData.AppName].Address

	tokenMiddleware := token.NewGinMiddleware(log)

	h := handler{
		ControllerStarter: NewGracefullyShutdown(log, router, address),
		userService:       userService,
		log:               log,
		jwt:               jwt,
		cfg:               cfg,
		tokenMiddleware:   tokenMiddleware,
	}

	// PING API
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, appData)
	})

	// CORS
	router.Use(cors.New(cors.Config{
		ExposeHeaders:   []string{"Data-Length"},
		AllowMethods:    []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
		AllowAllOrigins: true,
		AllowHeaders:    []string{"Content-Type", "Authorization"},
		MaxAge:          12 * time.Hour,
	}))

	prefixGroupName := router.Group("/user")

	v1 := prefixGroupName.Group("/v1")
	{
		v1.POST("/register", h.Register)
		v1.POST("/login", h.Login)
		v1.POST("/refresh-token", h.RefreshToken)
		v1.GET("/info", tokenMiddleware.Authentication(jwt), h.GetUserInfo)
	}

	return &h
}

// RefreshToken godoc
// @Summary refresh expired token
// @Schemes
// @Description refresh expired token
// @Tags RefreshToken
// @Accept       json
// @Produce      json
// @Param        request body RefreshTokenRequest true "body params"
// @Security 	 Bearer
// @Router       /user/v1/refresh-token [post]
func (h *handler) RefreshToken(c *gin.Context) {
	traceID := util.GenerateID(16)
	ctx := logger.SetTraceID(context.Background(), traceID)

	var jsonReq RefreshTokenRequest

	if err := c.ShouldBindJSON(&jsonReq); err == nil {
		validate := validator.New()
		if err = validate.Struct(&jsonReq); err != nil {
			h.log.Error(ctx, err.Error())
			c.JSON(http.StatusBadRequest, payload.NewErrorResponse(err, traceID))
			return
		}
	}

	oldToken, err := h.tokenMiddleware.GetAccessTokenFromHeader(c)
	if err != nil {
		h.log.Error(ctx, err.Error())
		c.JSON(http.StatusUnauthorized, payload.NewErrorResponse(err, traceID))
		return
	}

	newAccessToken, newRefreshToken, newCsrfSecret, expiresAt, _, err := h.jwt.RenewToken(ctx, oldToken, jsonReq.RefreshToken, jsonReq.CsrfSecret)
	if err != nil {
		h.log.Error(ctx, err.Error())
		c.JSON(http.StatusUnauthorized, payload.NewErrorResponse(err, traceID))
		return
	}

	c.JSON(http.StatusOK, payload.NewSuccessResponse(gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
		"csrf_secret":   newCsrfSecret,
		"expires_at":    expiresAt,
	}, traceID))

}

// GetUserInfo godoc
// @Summary get user information
// @Schemes
// @Description get user information
// @Tags GetUserInfo
// @Accept       json
// @Produce      json
// @Security 	 Bearer
// @Router       /user/v1/info [get]
func (h *handler) GetUserInfo(c *gin.Context) {
	traceID := util.GenerateID(16)
	ctx := logger.SetTraceID(context.Background(), traceID)

	userID := c.GetString("UserID")

	user, err := h.userService.GetUser(ctx, service.GetUserDTO{UserID: userID})
	if err != nil {
		h.log.Error(ctx, err.Error())
		c.JSON(http.StatusInternalServerError, payload.NewErrorResponse(err, traceID))
		return
	}

	c.JSON(http.StatusOK, payload.NewSuccessResponse(gin.H{
		"user": user,
	}, traceID))
}

// Register godoc
// @Summary register new user
// @Schemes
// @Description register new user
// @Tags Register
// @Accept       json
// @Produce      json
// @Param        request body RegisterRequest true "body params"
// @Router       /user/v1/register [post]
func (h *handler) Register(c *gin.Context) {
	traceID := util.GenerateID(16)
	ctx := logger.SetTraceID(context.Background(), traceID)

	var jsonReq RegisterRequest

	if err := c.ShouldBindJSON(&jsonReq); err == nil {
		validate := validator.New()
		if err = validate.Struct(&jsonReq); err != nil {
			h.log.Error(ctx, err.Error())
			c.JSON(http.StatusBadRequest, payload.NewErrorResponse(err, traceID))
			return
		}
	}

	err := h.userService.Register(ctx, service.RegisterDTO{
		FirstName: jsonReq.FirstName,
		LastName:  jsonReq.LastName,
		Email:     jsonReq.Email,
		Password:  jsonReq.Password,
	})
	if err != nil {
		h.log.Error(ctx, err.Error())
		c.JSON(http.StatusInternalServerError, payload.NewErrorResponse(err, traceID))
		return
	}

	c.JSON(http.StatusOK, payload.NewSuccessResponse(gin.H{
		"message": "register successfully!",
	}, traceID))
}

// Login godoc
// @Summary login user
// @Schemes
// @Description login user
// @Tags Login
// @Accept       json
// @Produce      json
// @Param        request body LoginRequest true "body params"
// @Router       /user/v1/login [post]
func (h *handler) Login(c *gin.Context) {
	traceID := util.GenerateID(16)
	ctx := logger.SetTraceID(context.Background(), traceID)

	var jsonReq LoginRequest

	if err := c.ShouldBindJSON(&jsonReq); err == nil {
		validate := validator.New()
		if err = validate.Struct(&jsonReq); err != nil {
			h.log.Error(ctx, err.Error())
			c.JSON(http.StatusBadRequest, payload.NewErrorResponse(err, traceID))
			return
		}
	}

	user, err := h.userService.Login(ctx, service.LoginDTO{
		Email:    jsonReq.Email,
		Password: jsonReq.Password,
	})
	if err != nil {
		h.log.Error(ctx, err.Error())
		c.JSON(http.StatusInternalServerError, payload.NewErrorResponse(err, traceID))
		return
	}

	accessToken, refreshToken, csrfSecret, expiresAt, err := h.jwt.GenerateToken(ctx, user.ID, user.ID)
	if err != nil {
		h.log.Error(ctx, err.Error())
		c.JSON(http.StatusUnauthorized, payload.NewErrorResponse(err, traceID))
		return
	}
	c.JSON(http.StatusOK, payload.NewSuccessResponse(gin.H{
		"user":          user,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"csrf_secret":   csrfSecret,
		"expires_at":    expiresAt,
	}, traceID))
}
