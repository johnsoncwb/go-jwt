package controllers

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/johnsoncwb/go-jwt/initializers"
	"github.com/johnsoncwb/go-jwt/models"
	"golang.org/x/crypto/bcrypt"
)

type response struct {
	Id    uint   `json:"id"`
	Email string `json:"email"`
}

func SignUp(c *gin.Context) {
	// get the email and password from req body
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}
	// hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate hash password",
		})
		return
	}
	// create the user
	user := models.User{Email: body.Email, Password: string(hash)}
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "error to create the user",
		})
		return
	}

	// respond

	c.JSON(http.StatusOK, gin.H{
		"data": "success",
	})
}

func Login(c *gin.Context) {
	// get the email and password from req body
	var body struct {
		Email    string
		Password string
	}
	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
	}
	// look up requested user
	var user models.User
	initializers.DB.First(&user, "Email = ?", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid Email or Password",
		})
		return
	}
	// compare sent in pass with saved user pass hash
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid Email or Password",
		})
	}
	// generate a jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})
	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create Token",
		})
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)

	// send it back
	c.JSON(http.StatusOK, gin.H{
		"data": tokenString,
	})
}

func Validade(c *gin.Context) {

	user, ok := c.Get("user")

	// add comment

	userResponse := response{
		Id:    user.(models.User).ID,
		Email: user.(models.User).Email,
	}

	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"data": "User not found.",
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"data": &userResponse,
	})
}
