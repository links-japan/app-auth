package auth

import (
	"context"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gin-gonic/gin"
	lru "github.com/hashicorp/golang-lru"
	"net/http"
	"strings"
	"time"
)

type Auth struct {
	storage Storage
	cache   *lru.ARCCache
	secret  string
	expiry  time.Duration

	clientID     string
	clientSecret string
}

func New(clientID, clientSecret string, storage Storage, cacheSize int, secret string, expiry time.Duration) (*Auth, error) {
	cache, err := lru.NewARC(cacheSize)
	if err != nil {
		return nil, err
	}

	return &Auth{
		clientID:     clientID,
		clientSecret: clientSecret,
		storage:      storage,
		cache:        cache,
		secret:       secret,
		expiry:       expiry,
	}, nil
}

func (a *Auth) PostAuth(ctx context.Context, code, lang string) (string, string, error) {

	accessToken, _, err := mixin.AuthorizeToken(ctx, a.clientID, a.clientSecret, code, "")
	if err != nil {
		return "", "", err
	}

	mixinUser, err := mixin.UserMe(ctx, accessToken)
	if err != nil {
		return "", "", err
	}

	a.cache.Remove(mixinUser.UserID)

	user := User{
		MixinUser:   mixinUser,
		AccessToken: accessToken,
		Lang:        lang,
	}

	if err := a.storage.UpsertUser(&user); err != nil {
		return "", "", err
	}

	token, err := a.SignAuthToken(mixinUser.UserID)

	return mixinUser.UserID, token, err
}

func (a *Auth) Refresh(ctx context.Context, userID, lang string) (string, error) {

	user := User{
		MixinUser: &mixin.User{
			UserID: userID,
		},
	}

	if err := a.storage.GetUser(&user); err != nil {
		return "", err
	}

	if _, err := mixin.UserMe(ctx, user.AccessToken); err != nil {
		a.cache.Remove(userID)
		return "", err
	}

	if err := a.storage.UpdateUser(&user, map[string]interface{}{"lang": lang}); err != nil {
		return "", err
	}

	return a.SignAuthToken(userID)
}

func (a *Auth) Client(c *gin.Context) (*mixin.Client, error) {
	userID := c.MustGet("user_id").(string)

	val, hit := a.cache.Get(userID)
	if hit {
		return mixin.NewFromAccessToken(val.(string)), nil
	}

	user := User{
		MixinUser: &mixin.User{
			UserID: userID,
		},
	}

	if err := a.storage.GetUser(&user); err != nil {
		return nil, err
	}

	a.cache.Add(userID, user.AccessToken)

	return mixin.NewFromAccessToken(user.AccessToken), nil
}

func (a *Auth) RequireAuth(c *gin.Context) {
	h := c.GetHeader("Authorization")
	s := strings.Split(h, "Bearer ")
	if len(s) < 2 || s[1] == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"msg": "invalid token",
		})
		c.Abort()
		return
	}

	payload, err := a.ValidateAuthToken(s[1])
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
