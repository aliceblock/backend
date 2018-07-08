package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"

	"github.com/aliceblock/backend/auth"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/spf13/viper"
)

func readConfig(filename string, defaults map[string]interface{}) (*viper.Viper, error) {
	v := viper.New()
	for key, value := range defaults {
		v.SetDefault(key, value)
	}
	v.SetConfigName(filename)
	v.AddConfigPath(".")
	v.AutomaticEnv()
	err := v.ReadInConfig()
	return v, err
}

func connectDB(connectionString string) *sql.DB {
	db, err := sql.Open("mysql", connectionString)
	if err != nil {
		panic(err)
	}
	return db
}

func main() {
	v1, err := readConfig("env", gin.H{
		"host":              os.Getenv("HOST"),
		"port":              os.Getenv("PORT"),
		"connection_string": "",
		"jwtToken":          "",
	})
	if err != nil {
		panic(fmt.Errorf("error when reading config: %v", err))
	}

	os.Setenv("HOST", v1.GetString("HOST"))
	os.Setenv("PORT", v1.GetString("PORT"))
	os.Setenv("jwtToken", v1.GetString("jwtToken"))

	db := connectDB(v1.GetString("CONNECTION_STRING"))
	r := gin.Default()

	auth.Router(r, db)

	r.GET("/test", func(c *gin.Context) {
		var num int
		err := db.QueryRow("SELECT 1+1").Scan(&num)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"type":    "success",
			"message": "Test OK",
			"results": num,
		})
	})
	r.Run()
}
