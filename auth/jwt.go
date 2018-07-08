package auth

import (
	"errors"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
)

type User struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	jwt.StandardClaims
}

func createTokenString(data map[string]interface{}) (string, error) {
	key := []byte(os.Getenv("jwtToken"))
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &User{
		ID:    data["id"].(int),
		Email: data["email"].(string),
	})
	tokenstring, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return tokenstring, nil
}

func verifyToken(requestToken string) (map[string]interface{}, error) {
	key := []byte(os.Getenv("jwtToken"))
	token, _ := jwt.Parse(requestToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("There was an error")
		}
		return key, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("Invalid authorization token")
}
