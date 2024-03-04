package token

import (
	"context"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/framework/model/payload"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/framework/util"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/logger"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

type GinMiddleware struct {
	log logger.Logger
}

func NewGinMiddleware(log logger.Logger) GinMiddleware {
	return GinMiddleware{log: log}
}

func (g GinMiddleware) GetAccessTokenFromHeader(c *gin.Context) (token string, err error) {

	if c.Request.Header["Authorization"] == nil || len(c.Request.Header["Authorization"]) == 0 {
		err = ErrUnauthorized
		return
	}

	authorization := strings.Split(c.Request.Header["Authorization"][0], " ")
	token = authorization[1]

	if authorization[0] != preTokenName {
		err = ErrUnauthorized
		return
	}

	if token == "" {
		err = ErrUnauthorized
		return
	}

	return
}

func (g GinMiddleware) Authentication(jwt JWT) gin.HandlerFunc {

	return func(c *gin.Context) {

		traceID := util.GenerateID(16)
		ctx := logger.SetTraceID(context.Background(), traceID)

		token, err := g.GetAccessTokenFromHeader(c)
		if err != nil {
			g.log.Error(ctx, err.Error())
			c.JSON(http.StatusUnauthorized, payload.NewErrorResponse(err, traceID))
			c.Abort()
			return
		}

		tokenClaims, err := jwt.VerifyToken(token)
		if err != nil {
			g.log.Error(ctx, err.Error())
			c.JSON(http.StatusUnauthorized, payload.NewErrorResponse(err, traceID))
			c.Abort()
			return
		}

		c.Set("TokenClaims", tokenClaims)
		c.Set("UserID", tokenClaims.UserID)

		c.Next()
	}
}
