package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/canonical/notary/internal/db"
)

type CreateAccountParams struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ChangeAccountParams struct {
	Password string `json:"password"`
}

type GetAccountResponse struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	Permissions int    `json:"permissions"`
}

type CreateAccountResponse struct {
	ID int `json:"id"`
}

type ChangeAccountResponse struct {
	ID int `json:"id"`
}

type DeleteAccountResponse struct {
	ID int `json:"id"`
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

// ListAccounts returns all accounts from the database
func ListAccounts(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accounts, err := env.DB.RetrieveAllUsers()
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		accountsResponse := make([]GetAccountResponse, len(accounts))
		for i, account := range accounts {
			accountsResponse[i] = GetAccountResponse{
				ID:          account.ID,
				Username:    account.Username,
				Permissions: account.Permissions,
			}
		}
		w.WriteHeader(http.StatusOK)
		err = writeJSON(w, accountsResponse)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}

// GetAccount receives an id as a path parameter, and
// returns the corresponding User Account
func GetAccount(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var account db.User
		var err error
		if id == "me" {
			claims, headerErr := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
			if headerErr != nil {
				writeError(w, http.StatusUnauthorized, "Unauthorized")
			}
			account, err = env.DB.RetrieveUserByUsername(claims.Username)
		} else {
			account, err = env.DB.RetrieveUser(id)
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
		accountResponse := GetAccountResponse{
			ID:          account.ID,
			Username:    account.Username,
			Permissions: account.Permissions,
		}
		w.WriteHeader(http.StatusOK)
		err = writeJSON(w, accountResponse)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}

// CreateAccount creates a new Account, and returns the id of the created row
func CreateAccount(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var createAccountParams CreateAccountParams
		if err := json.NewDecoder(r.Body).Decode(&createAccountParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}
		if createAccountParams.Username == "" {
			writeError(w, http.StatusBadRequest, "Username is required")
			return
		}
		if createAccountParams.Password == "" {
			writeError(w, http.StatusBadRequest, "Password is required")
			return
		}
		if !validatePassword(createAccountParams.Password) {
			writeError(
				w,
				http.StatusBadRequest,
				"Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol.",
			)
			return
		}
		numUsers, err := env.DB.NumUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to retrieve accounts: "+err.Error())
			return
		}

		permission := UserPermission
		if numUsers == 0 {
			permission = AdminPermission
		}
		id, err := env.DB.CreateUser(createAccountParams.Username, createAccountParams.Password, permission)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				writeError(w, http.StatusBadRequest, "account with given username already exists")
				return
			}
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		accountResponse := CreateAccountResponse{
			ID: int(id),
		}
		w.WriteHeader(http.StatusCreated)
		err = writeJSON(w, accountResponse)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}

// DeleteAccount handler receives an id as a path parameter,
// deletes the corresponding User Account, and returns a http.StatusNoContent on success
func DeleteAccount(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idInt, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		account, err := env.DB.RetrieveUser(id)
		if err != nil {
			if !errors.Is(err, db.ErrIdNotFound) {
				log.Println(err)
				writeError(w, http.StatusInternalServerError, "Internal Error")
				return
			}
		}
		if account.Permissions == 1 {
			writeError(w, http.StatusBadRequest, "deleting an Admin account is not allowed.")
			return
		}
		_, err = env.DB.DeleteUser(id)
		if err != nil {
			log.Println(err)
			if errors.Is(err, db.ErrIdNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		deleteAccountResponse := DeleteAccountResponse{
			ID: int(idInt),
		}
		w.WriteHeader(http.StatusAccepted)
		err = writeJSON(w, deleteAccountResponse)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}

func ChangeAccountPassword(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "me" {
			claims, err := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
			if err != nil {
				log.Println(err)
				writeError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			account, err := env.DB.RetrieveUserByUsername(claims.Username)
			if err != nil {
				log.Println(err)
				writeError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			id = strconv.Itoa(account.ID)
		}
		var changeAccountParams ChangeAccountParams
		if err := json.NewDecoder(r.Body).Decode(&changeAccountParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}
		if changeAccountParams.Password == "" {
			writeError(w, http.StatusBadRequest, "Password is required")
			return
		}
		if !validatePassword(changeAccountParams.Password) {
			writeError(
				w,
				http.StatusBadRequest,
				"Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol.",
			)
			return
		}
		ret, err := env.DB.UpdateUser(id, changeAccountParams.Password)
		if err != nil {
			log.Println(err)
			if errors.Is(err, db.ErrIdNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		changeAccountResponse := ChangeAccountResponse{
			ID: int(ret),
		}
		w.WriteHeader(http.StatusCreated)
		err = writeJSON(w, changeAccountResponse)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}
