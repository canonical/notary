package server_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	server "github.com/canonical/notary/internal/api"
	"github.com/canonical/notary/internal/db"
	"github.com/golang-jwt/jwt"
)

func TestLogin(t *testing.T) {
	testdb, err := db.NewDatabase(":memory:")
	if err != nil {
		log.Fatalf("couldn't create test sqlite db: %s", err)
	}
	env := &server.Environment{}
	env.DB = testdb
	env.JWTSecret = []byte("secret")
	ts := httptest.NewTLSServer(server.NewNotaryRouter(env))
	defer ts.Close()

	client := ts.Client()

	testCases := []struct {
		desc     string
		method   string
		path     string
		data     string
		response string
		status   int
	}{
		{
			desc:     "Create admin user",
			method:   "POST",
			path:     "/api/v1/accounts",
			data:     adminUser,
			response: "{\"id\":1}",
			status:   http.StatusCreated,
		},
		{
			desc:     "Login success",
			method:   "POST",
			path:     "/login",
			data:     adminUser,
			response: "",
			status:   http.StatusOK,
		},
		{
			desc:     "Login failure missing username",
			method:   "POST",
			path:     "/login",
			data:     invalidUser,
			response: "Username is required",
			status:   http.StatusBadRequest,
		},
		{
			desc:     "Login failure missing password",
			method:   "POST",
			path:     "/login",
			data:     noPasswordUser,
			response: "Password is required",
			status:   http.StatusBadRequest,
		},
		{
			desc:     "Login failure invalid password",
			method:   "POST",
			path:     "/login",
			data:     adminUserWrongPass,
			response: "error: The username or password is incorrect. Try again.",
			status:   http.StatusUnauthorized,
		},
		{
			desc:     "Login failure invalid username",
			method:   "POST",
			path:     "/login",
			data:     notExistingUser,
			response: "error: The username or password is incorrect. Try again.",
			status:   http.StatusUnauthorized,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			req, err := http.NewRequest(tC.method, ts.URL+tC.path, strings.NewReader(tC.data))
			if err != nil {
				t.Fatal(err)
			}
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resBody, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != tC.status || !strings.Contains(string(resBody), tC.response) {
				t.Errorf("expected response did not match.\nExpected vs Received status code: %d vs %d\nExpected vs Received body: \n%s\nvs\n%s\n", tC.status, res.StatusCode, tC.response, string(resBody))
			}
			if tC.desc == "Login success" && res.StatusCode == http.StatusOK {
				token, parseErr := jwt.Parse(string(resBody), func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
					}
					return []byte(env.JWTSecret), nil
				})
				if parseErr != nil {
					t.Errorf("Error parsing JWT: %v", parseErr)
					return
				}

				if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
					if claims["username"] != "testadmin" {
						t.Errorf("Username found in JWT does not match expected value.")
					} else if int(claims["permissions"].(float64)) != 1 {
						t.Errorf("Permissions found in JWT does not match expected value.")
					}
				} else {
					t.Errorf("Invalid JWT token or JWT claims are not readable")
				}
			}
		})
	}
}
