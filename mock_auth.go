package auth

import (
	"context"
	"crypto/sha1"
	"fmt"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gin-gonic/gin"
	lru "github.com/hashicorp/golang-lru"
	"net/http"
	"time"
)

type MockAuth struct {
	storage Storage
	cache   *lru.ARCCache
	secret  string
	expiry  time.Duration
}

func NewMockAuth(storage Storage, cacheSize int, secret string, expiry time.Duration) (*MockAuth, error) {
	cache, err := lru.NewARC(cacheSize)
	if err != nil {
		return nil, err
	}

	return &MockAuth{
		storage: storage,
		cache:   cache,
		secret:  secret,
		expiry:  expiry,
	}, nil
}

func (a *MockAuth) PostAuth(ctx context.Context, code, lang string) (string, string, error) {

	// take code as user id.
	userID := code
	inst := sha1.New()
	inst.Write([]byte(userID))
	h := inst.Sum([]byte(""))

	mixinUser := &mixin.User{
		UserID:         userID,
		IdentityNumber: fmt.Sprintf("%x", h[:16]),
		FullName:       fmt.Sprintf("%x", h[:16]),
	}

	a.cache.Remove(mixinUser.UserID)

	user := User{
		MixinUser:   mixinUser,
		Lang:        lang,
	}

	if err := a.storage.UpsertUser(&user); err != nil {
		return "", "", err
	}

	token, err := a.SignAuthToken(mixinUser.UserID)

	return mixinUser.UserID, token, err
}

func (a *MockAuth) Refresh(ctx context.Context, userID, lang string) (string, error) {
	user := User{
		MixinUser: &mixin.User{
			UserID: userID,
		},
	}

	if err := a.storage.GetUser(&user); err != nil {
		return "", err
	}

	if err := a.storage.UpdateUser(&user, map[string]interface{}{"lang": lang}); err != nil {
		return "", err
	}

	return a.SignAuthToken(userID)
}

func (a *MockAuth) Client(c *gin.Context) (*mixin.Client, error) {
	return nil, nil
}

func (a *MockAuth) RequireAuth(c *gin.Context) {
	t := readTokenFromHeader(c)
	if len(t) == 0 {
		t = readTokenFromCookie(c)
	}
	if len(t) == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{
			"msg": "invalid token",
		})
		c.Abort()
		return
	}

	payload, err := a.ValidateAuthToken(t)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"msg": "invalid token",
		})
		c.Abort()
		return
	}

	c.Set("user_id", payload.UserID)
	c.Next()
}
