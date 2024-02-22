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
	userService service.UserService
	log         logger.Logger
	jwtToken    token.JWTToken
	cfg         *configs.Config
}

func NewHandler(appData framework.ApplicationData, log logger.Logger, jwtToken token.JWTToken, cfg *configs.Config, userService service.UserService) *handler {
	router := gin.Default()

	address := cfg.Servers[appData.AppName].Address

	h := handler{
		ControllerStarter: NewGracefullyShutdown(log, router, address),
		userService:       userService,
		log:               log,
		jwtToken:          jwtToken,
		cfg:               cfg,
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
	}

	return &h
}

// Register godoc
// @Summary register new user
// @Schemes
// @Description register new user
// @Tags RegisterUser
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

	validate := validator.New()
	if err := validate.Struct(&jsonReq); err != nil {
		h.log.Error(ctx, err.Error())
		c.JSON(http.StatusBadRequest, payload.NewErrorResponse(err, traceID))
		return
	}

	err := h.userService.Register(ctx, jsonReq.FirstName, jsonReq.LastName, jsonReq.Email, jsonReq.Password)
	if err != nil {
		h.log.Error(ctx, err.Error())
		c.JSON(http.StatusInternalServerError, payload.NewErrorResponse(err, traceID))
		return
	}

	c.JSON(http.StatusOK, payload.NewSuccessResponse(gin.H{
		"message": "register successfully!",
	}, traceID))
}
