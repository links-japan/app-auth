package main

import (
	"fmt"
	auth "github.com/links-japan/app-auth"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"os"
	"time"
)

var db *gorm.DB

func Init() {
	if err := SetupConn(); err != nil {
		fmt.Println(err)
	}
	if err := db.AutoMigrate(&User{}); err != nil {
		fmt.Println(err)
	}

}

func SetupConn() error {
	dsn := os.Getenv("DATABASE_URL")

	conn, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}
	db = conn
	return nil
}

// User represents users table
type User struct {
	ID          uint64    `json:"-"`
	UserID      string    `gorm:"type:varchar(36);not null;index:idx_user_id" json:"user_id"`
	AccessToken string    `gorm:"size:511" json:"-"`
	CreatedAt   time.Time `json:"-"`
	UpdatedAt   time.Time `json:"-"`
}

type AuthStorage struct{}

func (s *AuthStorage) UpsertUser(u *auth.User) error {
	user := User{
		UserID:      u.MixinUser.UserID,
		AccessToken: u.AccessToken,
	}

	return db.Where("user_id = ?", user.UserID).Assign(user).FirstOrCreate(&user).Error
}

func (s *AuthStorage) GetUser(u *auth.User) error {
	user := User{
		UserID: u.MixinUser.UserID,
	}

	if err := db.Where("user_id = ?", user.UserID).First(user).Error; err != nil {
		return err
	}

	u.AccessToken = user.AccessToken

	return nil
}

func (s *AuthStorage) UpdateUser(u *auth.User, fields map[string]interface{}) error {
	user := User{
		UserID: u.MixinUser.UserID,
	}

	if err := db.Model(&User{}).Where("user_id = ?", user.UserID).Updates(fields).Error; err != nil {
		return err
	}

	return nil
}
