package main

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/links-japan/app-auth"
	"net/http"
	"os"
	"time"
)

var mixinAuth auth.Auth

func main() {
	Init()
	router := gin.Default()

	cache := auth.NewRedisCache(os.Getenv("REDIS_ADDR"))
	//cache, _ := auth.NewSimpleCache(1024)

	au, err := auth.NewMockAuth(
		&AuthStorage{},
		cache,
		"123",
		24*time.Hour)
	if err != nil {
		fmt.Println(err)
		return
	}

	mixinAuth = au

	api := router.Group("/api")
	{
		api.POST("/auth", postAuth)
		api.Use(mixinAuth.RequireAuth)
		{
			api.POST("/refresh_token", refreshToken)
			api.GET("/ping", func(c *gin.Context) { c.JSON(http.StatusOK, "pong") })
		}
	}

	if err := router.Run(":8080"); err != nil {
		fmt.Println(err)
	}
}

func postAuth(c *gin.Context) {
	type params struct {
		Code string `form:"code"`
	}
	var p params
	if err := c.ShouldBind(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid code",
		})
		return
	}

	userID, tok, err := mixinAuth.PostAuth(context.Background(), p.Code, "en")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"err": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, AuthResponse{
		Token:  tok,
		UserID: userID,
	})
}

type AuthResponse struct {
	Token  string `json:"token"`
	UserID string `json:"user_id"`
}

func refreshToken(c *gin.Context) {
	userID := c.MustGet("user_id").(string)

	type params struct {
		Lang string `form:"lang"`
	}
	var p params
	if err := c.ShouldBind(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid code",
		})
		return
	}

	nt, err := mixinAuth.Refresh(context.Background(), userID, p.Lang)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"err": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, AuthResponse{
		Token:  nt,
		UserID: userID,
	})
}
