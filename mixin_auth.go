package auth

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/fox-one/mixin-sdk-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
	"time"
)

type MixinAuth struct {
	storage      Storage
	secret       string
	expiry       time.Duration
	cache        Cache
	clientID     string
	clientSecret string
	phonePrefix  string
}

func New(clientID, clientSecret string, storage Storage, cache Cache, secret string, expiry time.Duration, phonePrefix string) (*MixinAuth, error) {

	return &MixinAuth{
		clientID:     clientID,
		clientSecret: clientSecret,
		storage:      storage,
		cache:        cache,
		secret:       secret,
		expiry:       expiry,
		phonePrefix:  phonePrefix,
	}, nil
}

func (a *MixinAuth) PostAuth(ctx context.Context, code, lang string) (string, string, error) {

	accessToken, _, err := mixin.AuthorizeToken(ctx, a.clientID, a.clientSecret, code, "")
	if err != nil {
		return "", "", err
	}

	mixinUser, err := mixin.UserMe(ctx, accessToken)
	if err != nil {
		return "", "", err
	}

	if !strings.HasPrefix(mixinUser.Phone, a.phonePrefix) {
		return "", "", errors.New("not japan phone number")
	}

	user := User{
		MixinUser:   mixinUser,
		AccessToken: accessToken,
		Lang:        lang,
	}

	if err = a.cache.Set(ctx, mixinUser.UserID, &user); err != nil {
		log.Println(err)
	}

	if err := a.storage.UpsertUser(&user); err != nil {
		return "", "", err
	}

	token, err := a.SignAuthToken(mixinUser.UserID)

	return mixinUser.UserID, token, err
}

func (a *MixinAuth) Refresh(ctx context.Context, userID, lang string) (string, error) {

	user := User{
		MixinUser: &mixin.User{
			UserID: userID,
		},
	}

	// try to get user from cache or database
	u, err := a.cache.Get(ctx, userID)
	if u == nil || err != nil {
		if err := a.storage.GetUser(&user); err != nil {
			return "", err
		}
		if err = a.cache.Set(ctx, userID, u); err != nil {
			log.Println(err)
		}
	} else {
		user = *u
	}

	// verify user's mixin access token
	mixinUser, err := mixin.UserMe(ctx, user.AccessToken)
	if err != nil {
		if err := a.cache.Remove(ctx, userID); err != nil {
			log.Println(err)
		}
		return "", err
	}

	if !strings.HasPrefix(mixinUser.Phone, a.phonePrefix) {
		return "", errors.New("not japan phone number")
	}

	// if user lang change update user lang
	if user.Lang != lang {
		if err := a.storage.UpdateUser(&user, map[string]interface{}{"lang": lang}); err != nil {
			return "", err
		}
	}

	return a.SignAuthToken(userID)
}

func (a *MixinAuth) Client(c *gin.Context) (*mixin.Client, error) {
	userID := c.MustGet("user_id").(string)

	u, err := a.cache.Get(context.TODO(), userID)
	if err != nil {
		log.Println(err)
	}
	if u != nil {
		return mixin.NewFromAccessToken(u.AccessToken), nil
	}

	user := User{
		MixinUser: &mixin.User{
			UserID: userID,
		},
	}

	if err := a.storage.GetUser(&user); err != nil {
		return nil, err
	}

	return mixin.NewFromAccessToken(user.AccessToken), nil
}

func (a *MixinAuth) RequireAuth(c *gin.Context) {
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

func (a *MixinAuth) SetUserWhenExists(c *gin.Context) {
	t := readTokenFromHeader(c)
	if len(t) == 0 {
		t = readTokenFromCookie(c)
	}
	if len(t) == 0 {
		c.Next()
		return
	}
	payload, err := a.ValidateAuthToken(t)
	if err != nil {
		c.Next()
		return
	}

	c.Set("user_id", payload.UserID)
	c.Next()
}

func readTokenFromHeader(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	s := strings.Split(h, "Bearer ")
	if len(s) < 2 || s[1] == "" {
		return ""
	}
	return fmt.Sprintf("%s", s[1])
}

func readTokenFromCookie(c *gin.Context) string {
	cookie, err := c.Cookie("token")
	if err != nil {
		return ""
	}
	return cookie
}
