package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"

	"github.com/canonical/notary/internal/db"
)

type CreateAccountParams struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (params *CreateAccountParams) IsValid() (bool, error) {
	if params.Username == "" {
		return false, errors.New("username is required")
	}
	if params.Password == "" {
		return false, errors.New("password is required")
	}
	if !validatePassword(params.Password) {
		return false, errors.New("Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol.")
	}
	return true, nil
}

type ChangeAccountParams struct {
	Password string `json:"password"`
}

func (params *ChangeAccountParams) IsValid() (bool, error) {
	if params.Password == "" {
		return false, errors.New("password is required")
	}
	if !validatePassword(params.Password) {
		return false, errors.New("Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol.")
	}
	return true, nil
}

type GetAccountResponse struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Permissions int    `json:"permissions"`
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
		accounts, err := env.DB.ListUsers()
		if err != nil {
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
		err = writeResponse(w, accountsResponse, http.StatusOK)
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
		var account *db.User
		var err error
		if id == "me" {
			claims, headerErr := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
			if headerErr != nil {
				writeError(w, http.StatusUnauthorized, "Unauthorized")
			}
			account, err = env.DB.GetUser(db.ByUsername(claims.Username))
		} else {
			var idNum int64
			idNum, err = strconv.ParseInt(id, 10, 64)
			if err != nil {
				writeError(w, http.StatusBadRequest, "Invalid ID")
				return
			}
			account, err = env.DB.GetUser(db.ByUserID(idNum))
		}
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
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
		err = writeResponse(w, accountResponse, http.StatusOK)
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
		valid, err := createAccountParams.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error())
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
		numUsers, err := env.DB.NumUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to retrieve accounts: "+err.Error())
			return
		}
		permission := UserPermission
		if numUsers == 0 {
			permission = AdminPermission
		}
		newUserID, err := env.DB.CreateUser(createAccountParams.Username, createAccountParams.Password, permission)
		if err != nil {
			if errors.Is(err, db.ErrAlreadyExists) {
				writeError(w, http.StatusBadRequest, "account with given username already exists")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		successResponse := CreateSuccessResponse{Message: "success", ID: newUserID}
		err = writeResponse(w, successResponse, http.StatusCreated)
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
			writeError(w, http.StatusBadRequest, "Invalid ID")
			return
		}
		account, err := env.DB.GetUser(db.ByUserID(idInt))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		if account.Permissions == 1 {
			writeError(w, http.StatusBadRequest, "deleting an Admin account is not allowed.")
			return
		}
		err = env.DB.DeleteUser(db.ByUserID(idInt))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusAccepted)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}

func ChangeAccountPassword(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var idNum int64
		if id == "me" {
			claims, err := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
			if err != nil {
				log.Println(err)
				writeError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			account, err := env.DB.GetUser(db.ByUsername(claims.Username))
			if err != nil {
				writeError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			idNum = account.ID
		} else {
			idInt, err := strconv.ParseInt(id, 10, 64)
			if err != nil {
				log.Println(err)
				writeError(w, http.StatusBadRequest, "Invalid ID")
				return
			}
			idNum = idInt
		}
		var changeAccountParams ChangeAccountParams
		if err := json.NewDecoder(r.Body).Decode(&changeAccountParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}
		valid, err := changeAccountParams.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error())
			return
		}
		err = env.DB.UpdateUserPassword(db.ByUserID(idNum), changeAccountParams.Password)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}
