package auth

import (
	"context"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gin-gonic/gin"
)

type Auth interface {
	PostAuth(ctx context.Context, code, lang string) (string, string, error)
	Refresh(ctx context.Context, userID, lang string) (string, error)
	Client(c *gin.Context) (*mixin.Client, error)
	RequireAuth(c *gin.Context)
	SignAuthToken(userID string) (string, error)
	ValidateAuthToken(tok string) (*Payload, error)
}
