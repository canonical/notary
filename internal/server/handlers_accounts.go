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
	ID     int64  `json:"id"`
	Email  string `json:"email"`
	RoleID RoleID `json:"role_id"`
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
func ListAccounts(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accounts, err := env.DB.ListUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
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
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
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
				writeError(w, http.StatusUnauthorized, "Unauthorized", headerErr, env.SystemLogger)
			}
			account, err = env.DB.GetUser(db.ByEmail(claims.Email))
		} else {
			var idNum int64
			idNum, err = strconv.ParseInt(id, 10, 64)
			if err != nil {
				writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
				return
			}
			account, err = env.DB.GetUser(db.ByUserID(idNum))
		}
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		accountResponse := GetAccountResponse{
			ID:     account.ID,
			Email:  account.Email,
			RoleID: RoleID(account.RoleID),
		}
		err = writeResponse(w, accountResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// CreateAccount creates a new Account, and returns the id of the created row
func CreateAccount(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var createAccountParams CreateAccountParams
		if err := json.NewDecoder(r.Body).Decode(&createAccountParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.SystemLogger)
			return
		}
		valid, err := createAccountParams.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error(), err, env.SystemLogger)
			return
		}
		newUserID, err := env.DB.CreateUser(createAccountParams.Email, createAccountParams.Password, db.RoleID(createAccountParams.RoleID))
		if err != nil {
			if errors.Is(err, db.ErrAlreadyExists) {
				writeError(w, http.StatusBadRequest, "account with given email already exists", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		var actor string
		claims, claimsErr := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
		if claimsErr == nil {
			actor = claims.Email
		}
		
		opts := []AuditOption{WithRequest(r)}
		if actor != "" {
			opts = append(opts, WithActor(actor))
		}
		env.AuditLogger.UserCreated(createAccountParams.Email, int(createAccountParams.RoleID), opts...)
		
		successResponse := CreateSuccessResponse{Message: "success", ID: newUserID}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
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
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}
		account, err := env.DB.GetUser(db.ByUserID(idInt))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		if account.RoleID == db.RoleID(RoleAdmin) {
			err = errors.New("deleting an Admin account is not allowed")
			writeError(w, http.StatusBadRequest, "deleting an Admin account is not allowed.", err, env.SystemLogger)
			return
		}

		claims, err := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, env.SystemLogger)
			return
		}

		err = env.DB.DeleteUser(db.ByUserID(idInt))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		env.AuditLogger.UserDeleted(account.Email,
			WithActor(claims.Email),
			WithRequest(r),
		)

		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusAccepted)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

func ChangeAccountPassword(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var idNum int64
		idInt, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}
		idNum = idInt

		targetAccount, err := env.DB.GetUser(db.ByUserID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		claims, err := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, env.SystemLogger)
			return
		}

		var changeAccountParams ChangeAccountParams
		if err := json.NewDecoder(r.Body).Decode(&changeAccountParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.SystemLogger)
			return
		}
		valid, err := changeAccountParams.IsValid()
		if !valid {
			env.AuditLogger.PasswordChangeFailed(targetAccount.Email,
				WithActor(claims.Email),
				WithRequest(r),
				WithReason(err.Error()),
			)
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error(), err, env.SystemLogger)
			return
		}
		err = env.DB.UpdateUserPassword(db.ByUserID(idNum), changeAccountParams.Password)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				env.AuditLogger.PasswordChangeFailed(targetAccount.Email,
					WithActor(claims.Email),
					WithRequest(r),
					WithReason("user not found"),
				)
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			env.AuditLogger.PasswordChangeFailed(targetAccount.Email,
				WithActor(claims.Email),
				WithRequest(r),
				WithReason("database error"),
			)
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		env.AuditLogger.PasswordChanged(targetAccount.Email,
			WithActor(claims.Email),
			WithRequest(r),
		)
		env.AuditLogger.UserUpdated(targetAccount.Email, "password_change",
			WithActor(claims.Email),
			WithRequest(r),
		)

		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

func ChangeMyPassword(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var idNum int64
		claims, err := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, env.SystemLogger)
			return
		}
		account, err := env.DB.GetUser(db.ByEmail(claims.Email))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, env.SystemLogger)
			return
		}
		idNum = account.ID
		var changeAccountParams ChangeAccountParams
		if err := json.NewDecoder(r.Body).Decode(&changeAccountParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.SystemLogger)
			return
		}
		valid, err := changeAccountParams.IsValid()
		if !valid {
			env.AuditLogger.PasswordChangeFailed(account.Email,
				WithRequest(r),
				WithReason(err.Error()),
			)
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error(), err, env.SystemLogger)
			return
		}
		err = env.DB.UpdateUserPassword(db.ByUserID(idNum), changeAccountParams.Password)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				env.AuditLogger.PasswordChangeFailed(account.Email,
					WithRequest(r),
					WithReason("user not found"),
				)
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			env.AuditLogger.PasswordChangeFailed(account.Email,
				WithRequest(r),
				WithReason("database error"),
			)
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		env.AuditLogger.PasswordChanged(account.Email, WithRequest(r))
		env.AuditLogger.UserUpdated(account.Email, "password_change", WithRequest(r))
		
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}
