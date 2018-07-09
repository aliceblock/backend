package auth

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func GetBodyData(c *gin.Context) (map[string]interface{}, error) {
	data := map[string]interface{}{}

	if c.ContentType() == "application/x-www-form-urlencoded" {
		if err := c.Request.ParseForm(); err != nil {
			return nil, err
		}
		for key, value := range c.Request.PostForm {
			data[key] = value[0]
		}
	} else {
		c.Bind(&data)
	}

	return data, nil
}

func Router(engine *gin.Engine, db *sql.DB) {
	auth := engine.Group("/auth")
	{
		auth.POST("/login", func(c *gin.Context) {
			var qID int
			var qPassword string
			var email string
			var password string

			data, err := GetBodyData(c)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"type":    "error",
					"message": "parsing form error.",
				})
				return
			}
			email, password = data["email"].(string), data["password"].(string)

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

		auth.POST("/google", func(c *gin.Context) {
			var token string
			var ok bool
			data, err := GetBodyData(c)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"type":    "error",
					"message": "parsing form error.",
				})
				return
			}
			if token, ok = data["token"].(string); !ok {
				c.JSON(http.StatusInternalServerError, gin.H{
					"type":    "error",
					"message": "No access token provided.",
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"type":    "success",
				"message": "Google OAuth2",
				"token":   token,
			})
			return
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
