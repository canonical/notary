package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"regexp"
	"strconv"

	"github.com/canonical/notary/internal/db"
)

type CreateAccountParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	RoleID   RoleID `json:"role_id"`
}

func (params *CreateAccountParams) IsValid() (bool, error) {
	if params.Email == "" {
		return false, errors.New("email is required")
	}
	if !validateEmail(params.Email) {
		return false, errors.New("invalid email format")
	}
	if params.Password == "" {
		return false, errors.New("password is required")
	}
	if !params.RoleID.IsValid() {
		return false, fmt.Errorf("invalid role ID: %d", params.RoleID)
	}
	if !validatePassword(params.Password) {
		return false, errors.New("password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol")
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
		return false, errors.New("password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol")
	}
	return true, nil
}

type GetAccountResponse struct {
	ID     int64  `json:"id,omitempty"`
	Email  string `json:"email"`
	RoleID RoleID `json:"role_id,omitempty"`
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

func validateEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// ListAccounts returns all accounts from the database
func ListAccounts(env *HandlerOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accounts, err := env.DB.ListUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.Logger)
			return
		}
		accountsResponse := make([]GetAccountResponse, len(accounts))
		for i, account := range accounts {
			accountsResponse[i] = GetAccountResponse{
				ID:     account.ID,
				Email:  account.Email,
				RoleID: RoleID(account.RoleID),
			}
		}
		err = writeResponse(w, accountsResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.Logger)
			return
		}
	}
}

// GetAccount receives an id as a path parameter, and
// returns the corresponding User Account
// It can only return accounts that exist in the database
// If the account was logged in with OIDC, it will only return the email
func GetAccount(env *HandlerOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var account *db.User
		var err error
		if id == "me" {
			claims, jwtErr := getClaimsFromCookie(r, env.JWTSecret, env.OIDCConfig)
			if jwtErr != nil {
				writeError(w, http.StatusUnauthorized, "Unauthorized", jwtErr, env.Logger)
			}
			account = &db.User{
				Email: claims.Email,
			}
		} else {
			var idNum int64
			idNum, err = strconv.ParseInt(id, 10, 64)
			if err != nil {
				writeError(w, http.StatusBadRequest, "Invalid ID", err, env.Logger)
				return
			}
			account, err = env.DB.GetUser(db.ByUserID(idNum))
		}
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.Logger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.Logger)
			return
		}
		accountResponse := GetAccountResponse{
			ID:     account.ID,
			Email:  account.Email,
			RoleID: RoleID(account.RoleID),
		}
		err = writeResponse(w, accountResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.Logger)
			return
		}
	}
}

// GetMyAccount receives "me" as a path parameter, and
// returns the corresponding User Account. Unlike GetAccount,
// it uses the JWT claims to retrieve the account information.
func GetMyAccount(env *HandlerOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var account *db.User
		var err error
		claims, jwtErr := getClaimsFromCookie(r, env.JWTSecret, env.OIDCConfig)
		if jwtErr != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", jwtErr, env.Logger)
		}
		account = &db.User{
			Email: claims.Email,
		}
		accountResponse := GetAccountResponse{
			ID:     account.ID,
			Email:  account.Email,
			RoleID: RoleID(account.RoleID),
		}
		err = writeResponse(w, accountResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.Logger)
			return
		}
	}
}

// CreateAccount creates a new Account, and returns the id of the created row
func CreateAccount(env *HandlerOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var createAccountParams CreateAccountParams
		if err := json.NewDecoder(r.Body).Decode(&createAccountParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.Logger)
			return
		}
		valid, err := createAccountParams.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error(), err, env.Logger)
			return
		}
		newUserID, err := env.DB.CreateUser(createAccountParams.Email, createAccountParams.Password, db.RoleID(createAccountParams.RoleID))
		if err != nil {
			if errors.Is(err, db.ErrAlreadyExists) {
				writeError(w, http.StatusBadRequest, "account with given email already exists", err, env.Logger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.Logger)
			return
		}
		successResponse := CreateSuccessResponse{Message: "success", ID: newUserID}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.Logger)
			return
		}
	}
}

// DeleteAccount handler receives an id as a path parameter,
// deletes the corresponding User Account, and returns a http.StatusNoContent on success
func DeleteAccount(env *HandlerOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idInt, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.Logger)
			return
		}
		account, err := env.DB.GetUser(db.ByUserID(idInt))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.Logger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.Logger)
			return
		}
		if account.RoleID == db.RoleID(RoleAdmin) {
			err = errors.New("deleting an Admin account is not allowed")
			writeError(w, http.StatusBadRequest, "deleting an Admin account is not allowed.", err, env.Logger)
			return
		}
		err = env.DB.DeleteUser(db.ByUserID(idInt))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.Logger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.Logger)
			return
		}
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusAccepted)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.Logger)
			return
		}
	}
}

func ChangeAccountPassword(env *HandlerOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var idNum int64
		idInt, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.Logger)
			return
		}
		idNum = idInt
		var changeAccountParams ChangeAccountParams
		if err := json.NewDecoder(r.Body).Decode(&changeAccountParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.Logger)
			return
		}
		valid, err := changeAccountParams.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error(), err, env.Logger)
			return
		}
		err = env.DB.UpdateUserPassword(db.ByUserID(idNum), changeAccountParams.Password)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.Logger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.Logger)
			return
		}
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.Logger)
			return
		}
	}
}

func ChangeMyPassword(env *HandlerOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var idNum int64
		claims, err := getClaimsFromCookie(r, env.JWTSecret, env.OIDCConfig)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, env.Logger)
			return
		}
		account, err := env.DB.GetUser(db.ByEmail(claims.Email))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, env.Logger)
			return
		}
		idNum = account.ID
		var changeAccountParams ChangeAccountParams
		if err := json.NewDecoder(r.Body).Decode(&changeAccountParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.Logger)
			return
		}
		valid, err := changeAccountParams.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error(), err, env.Logger)
			return
		}
		err = env.DB.UpdateUserPassword(db.ByUserID(idNum), changeAccountParams.Password)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.Logger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.Logger)
			return
		}
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.Logger)
			return
		}
	}
}
