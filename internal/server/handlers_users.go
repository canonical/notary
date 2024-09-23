package server

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"math/big"
	mrand "math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/canonical/notary/internal/db"
)

func getRandomChars(charset string, length int) (string, error) {
	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[n.Int64()]
	}
	return string(result), nil
}

// Generates a random 16 chars long password that contains uppercase and lowercase characters and numbers or symbols.
func generatePassword() (string, error) {
	const (
		uppercaseSet         = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lowercaseSet         = "abcdefghijklmnopqrstuvwxyz"
		numbersAndSymbolsSet = "0123456789*?@"
		allCharsSet          = uppercaseSet + lowercaseSet + numbersAndSymbolsSet
	)
	uppercase, err := getRandomChars(uppercaseSet, 2)
	if err != nil {
		return "", err
	}
	lowercase, err := getRandomChars(lowercaseSet, 2)
	if err != nil {
		return "", err
	}
	numbersOrSymbols, err := getRandomChars(numbersAndSymbolsSet, 2)
	if err != nil {
		return "", err
	}
	allChars, err := getRandomChars(allCharsSet, 10)
	if err != nil {
		return "", err
	}
	res := []rune(uppercase + lowercase + numbersOrSymbols + allChars)
	mrand.Shuffle(len(res), func(i, j int) {
		res[i], res[j] = res[j], res[i]
	})
	return string(res), nil
}

func validatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	hasCapital := regexp.MustCompile(`[A-Z]`).MatchString(password)
	if !hasCapital {
		return false
	}
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	if !hasLower {
		return false
	}
	hasNumberOrSymbol := regexp.MustCompile(`[0-9!@#$%^&*()_+\-=\[\]{};':"|,.<>?~]`).MatchString(password)

	return hasNumberOrSymbol
}

// GetUserAccounts returns all users from the database
func GetUserAccounts(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := env.DB.RetrieveAllUsers()
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		for i := range users {
			users[i].Password = ""
		}
		body, err := json.Marshal(users)
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		if _, err := w.Write(body); err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
		}
	}
}

// GetUserAccount receives an id as a path parameter, and
// returns the corresponding User Account
func GetUserAccount(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var userAccount db.User
		var err error
		if id == "me" {
			claims, headerErr := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
			if headerErr != nil {
				writeError(w, http.StatusUnauthorized, "Unauthorized")
			}
			userAccount, err = env.DB.RetrieveUserByUsername(claims.Username)
		} else {
			userAccount, err = env.DB.RetrieveUser(id)
		}
		if err != nil {
			log.Println(err)
			if errors.Is(err, db.ErrIdNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		userAccount.Password = ""
		body, err := json.Marshal(userAccount)
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		if _, err := w.Write(body); err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
		}
	}
}

// PostUserAccount creates a new User Account, and returns the id of the created row
func PostUserAccount(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user db.User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}
		if user.Username == "" {
			writeError(w, http.StatusBadRequest, "Username is required")
			return
		}
		shouldGeneratePassword := user.Password == ""
		if shouldGeneratePassword {
			generatedPassword, err := generatePassword()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Failed to generate password")
				return
			}
			user.Password = generatedPassword
		}
		if !validatePassword(user.Password) {
			writeError(
				w,
				http.StatusBadRequest,
				"Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol.",
			)
			return
		}
		users, err := env.DB.RetrieveAllUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to retrieve users: "+err.Error())
			return
		}

		permission := UserPermission
		if len(users) == 0 {
			permission = AdminPermission
		}
		id, err := env.DB.CreateUser(user.Username, user.Password, permission)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				writeError(w, http.StatusBadRequest, "user with given username already exists")
				return
			}
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		response, err := json.Marshal(map[string]any{"id": id})
		if shouldGeneratePassword {
			response, err = json.Marshal(map[string]any{"id": id, "password": user.Password})
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Error marshaling response")
		}
		if _, err := w.Write(response); err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
		}
	}
}

// DeleteUserAccount handler receives an id as a path parameter,
// deletes the corresponding User Account, and returns a http.StatusNoContent on success
func DeleteUserAccount(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		user, err := env.DB.RetrieveUser(id)
		if err != nil {
			if !errors.Is(err, db.ErrIdNotFound) {
				log.Println(err)
				writeError(w, http.StatusInternalServerError, "Internal Error")
				return
			}
		}
		if user.Permissions == 1 {
			writeError(w, http.StatusBadRequest, "deleting an Admin account is not allowed.")
			return
		}
		insertId, err := env.DB.DeleteUser(id)
		if err != nil {
			log.Println(err)
			if errors.Is(err, db.ErrIdNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		w.WriteHeader(http.StatusAccepted)
		if _, err := w.Write([]byte(strconv.FormatInt(insertId, 10))); err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
		}
	}
}

func ChangeUserAccountPassword(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "me" {
			claims, err := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
			if err != nil {
				log.Println(err)
				writeError(w, http.StatusUnauthorized, "Unauthorized")
			}
			userAccount, err := env.DB.RetrieveUserByUsername(claims.Username)
			if err != nil {
				log.Println(err)
				writeError(w, http.StatusUnauthorized, "Unauthorized")
			}
			id = strconv.Itoa(userAccount.ID)
		}
		var user db.User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}
		if user.Password == "" {
			writeError(w, http.StatusBadRequest, "Password is required")
			return
		}
		if !validatePassword(user.Password) {
			writeError(
				w,
				http.StatusBadRequest,
				"Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol.",
			)
			return
		}
		ret, err := env.DB.UpdateUser(id, user.Password)
		if err != nil {
			log.Println(err)
			if errors.Is(err, db.ErrIdNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(strconv.FormatInt(ret, 10))); err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
		}
	}
}
