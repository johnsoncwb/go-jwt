package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/johnsoncwb/go-jwt/controllers"
	"github.com/johnsoncwb/go-jwt/initializers"
	"github.com/johnsoncwb/go-jwt/middleware"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDB()
}

func main() {

	route := gin.Default()

	route.GET("/alive", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"data": "alive",
		})
	})
	route.POST("/signup", controllers.SignUp)
	route.POST("/login", controllers.Login)
	route.GET("/validate", middleware.RequireAuth, controllers.Validade)

	route.Run()

}
