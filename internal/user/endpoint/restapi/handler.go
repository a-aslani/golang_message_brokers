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

	v1 := router.Group("/v1")
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
// @Router       /v1/register [post]
func (h *handler) Register(c *gin.Context) {
	traceID := util.GenerateID(16)
	ctx := logger.SetTraceID(context.Background(), traceID)

	err := h.userService.Register(ctx, "my name", "my lastname", "email@domain.com", "123456")
	if err != nil {
		h.log.Error(ctx, err.Error())
		c.JSON(http.StatusBadRequest, payload.NewErrorResponse(err, traceID))
		return
	}

	c.JSON(http.StatusOK, payload.NewSuccessResponse(map[string]interface{}{
		"message": "ok",
	}, traceID))
}
