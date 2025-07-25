package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/gavintan/gopkg/aes"
	"gorm.io/gorm"
)

type User struct {
	ID        uint      `gorm:"primarykey" json:"id" form:"id"`
	Username  string    `gorm:"uniqueIndex;column:username" json:"username" form:"username"`
	Password  string    `form:"password" json:"password"`
	IsEnable  *bool     `gorm:"default:true" form:"isEnable" json:"isEnable"`
	Name      string    `json:"name" form:"name"`
	IpAddr    string    `gorm:"uniqueIndex;default:NULL" json:"ipAddr" form:"ipAddr"`
	CreatedAt time.Time `json:"createdAt,omitempty" form:"createdAt,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty" form:"updatedAt,omitempty"`
}

func (u *User) BeforeSave(tx *gorm.DB) (err error) {
	if u.Password != "" {
		ep, _ := aes.AesEncrypt(u.Password, os.Getenv("SECRET_KEY"))
		tx.Statement.SetColumn("Password", ep)
	}

	return
}

func (u *User) AfterFind(tx *gorm.DB) (err error) {
	dp, err := aes.AesDecrypt(u.Password, os.Getenv("SECRET_KEY"))
	if err == nil {
		u.Password = dp
	}

	return
}

func (u *User) All() []User {
	var users []User

	result := db.Model(&User{}).WithContext(context.Background()).Find(&users)
	if result.Error != nil {
		logger.Error(context.Background(), result.Error.Error())
		return []User{}
	}

	return users
}

func (u *User) Create() error {
	if u.Username == "" || u.Password == "" {
		return fmt.Errorf("Illegal request or Invalid request")
	}

	result := db.Create(&u)
	return result.Error
}

func (u *User) Update() error {
	result := db.Model(&u).Updates(&u)
	return result.Error
}

func (u *User) Delete(id string) error {
	result := db.Unscoped().Delete(&User{}, id)
	return result.Error
}

func (u *User) Login() error {
	pass := u.Password
	result := db.First(&u, "username = ?", u.Username)

	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return fmt.Errorf("Username does not exist")
	}

	if !*u.IsEnable {
		return fmt.Errorf("Account has been disabled")
	}

	if u.Password != pass {
		return fmt.Errorf("Incorrect password")
	}

	return nil

}

func (User) TableName() string {
	return "user"
}
