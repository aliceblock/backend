package auth

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func Router(engine *gin.Engine, db *sql.DB) {
	auth := engine.Group("/auth")
	{
		auth.POST("/login", func(c *gin.Context) {
			var qID int
			var qPassword string
			var email string
			var password string

			if strings.Contains(c.Request.Header.Get("Content-Type"), "application/json") {
				var data map[string]interface{}
				c.BindJSON(&data)
				email = data["email"].(string)
				password = data["password"].(string)
			} else {
				email = c.PostForm("email")
				password = c.PostForm("password")
			}

			if email == "" || password == "" {
				c.JSON(http.StatusBadRequest, gin.H{
					"type":    "error",
					"message": "email and password fields are essential for authentication.",
				})
				return
			}

			query, err := db.Query("SELECT id, password FROM users WHERE email=?", email)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"type":    "error",
					"message": "db error",
				})
				return
			}
			defer query.Close()

			if query.Next() {
				err = query.Scan(&qID, &qPassword)
			}
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"type":    "error",
					"message": "query error.",
				})
				return
			}
			if qID == 0 {
				c.JSON(http.StatusForbidden, gin.H{
					"type":    "error",
					"message": "User with provided email not found in database.",
				})
				return
			}

			err = bcrypt.CompareHashAndPassword([]byte(qPassword), []byte(password))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"type":    "error",
					"message": "bcrypt error",
				})
				return
			}

			token, err := createTokenString(map[string]interface{}{
				"id":    qID,
				"email": email,
			})
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"type":    "error",
					"message": "create token error",
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"type":    "success",
				"message": "User logged in.",
				"user": gin.H{
					"id":    qID,
					"email": email,
				},
				"token": token,
			})
		})

		auth.GET("/me", func(c *gin.Context) {
			token := c.Request.Header.Get("x-access-token")

			if token == "" {
				c.JSON(http.StatusBadRequest, gin.H{
					"type":    "error",
					"message": "x-access-token header not found.",
				})
				return
			}

			result, err := verifyToken(token)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{
					"type":    "error",
					"message": "Provided token is invalid.",
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"type":    "success",
				"message": "Provided token is valid.",
				"result":  result,
			})
		})
	}
}
