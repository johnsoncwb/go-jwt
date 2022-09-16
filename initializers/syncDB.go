package initializers

import "github.com/johnsoncwb/go-jwt/models"

func SyncDB() {
	DB.AutoMigrate(&models.User{})
}
