package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"regexp"
	"strconv"

	"github.com/canonical/notary/internal/backends/authorization"
	"github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
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
	ID          int64    `json:"id,omitempty"`
	Email       string   `json:"email"`
	RoleID      RoleID   `json:"role_id"` // Removed omitempty - role_id=0 (Admin) must be included
	HasPassword bool     `json:"has_password"`
	HasOIDC     bool     `json:"has_oidc"`
	OIDCSubject *string  `json:"oidc_subject,omitempty"`
	AuthMethods []string `json:"auth_methods"`
}

// userToAccountResponse converts a db.User to GetAccountResponse
func userToAccountResponse(user *db.User) GetAccountResponse {
	authMethods := []string{}
	if user.HasPassword() {
		authMethods = append(authMethods, "local")
	}
	if user.HasOIDC() {
		authMethods = append(authMethods, "oidc")
	}

	return GetAccountResponse{
		ID:          user.ID,
		Email:       user.Email,
		RoleID:      RoleID(user.RoleID),
		HasPassword: user.HasPassword(),
		HasOIDC:     user.HasOIDC(),
		OIDCSubject: user.OIDCSubject,
		AuthMethods: authMethods,
	}
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

// ListAccounts godoc
//
//	@Summary		List accounts
//	@Description	Returns all user accounts.
//	@Tags			accounts
//	@Produce		json
//	@Success		200	{object}	map[string][]GetAccountResponse
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/accounts [get]
func ListAccounts(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accounts, err := env.Database.ListUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		accountsResponse := make([]GetAccountResponse, len(accounts))
		for i, account := range accounts {
			accountsResponse[i] = userToAccountResponse(&account)
		}
		err = writeResponse(w, accountsResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// GetAccount godoc
//
//	@Summary		Get account
//	@Description	Returns the user account for the provided account ID.
//	@Tags			accounts
//	@Produce		json
//	@Param			id	path		int	true	"Account ID"
//	@Success		200	{object}	map[string]GetAccountResponse
//	@Failure		400	{object}	map[string]string
//	@Failure		401	{object}	map[string]string
//	@Failure		404	{object}	map[string]string
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/accounts/{id} [get]
func GetAccount(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var account *db.User
		var err error
		if id == "me" {
			claims, jwtErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
			if jwtErr != nil {
				writeError(w, http.StatusUnauthorized, "Unauthorized", jwtErr, env.SystemLogger)
				return
			}
			account = &db.User{
				Email: claims.Email,
			}
		} else {
			var idNum int64
			idNum, err = strconv.ParseInt(id, 10, 64)
			if err != nil {
				writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
				return
			}
			account, err = env.Database.GetUser(db.ByUserID(idNum))
		}
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		accountResponse := userToAccountResponse(account)
		err = writeResponse(w, accountResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// GetMyAccount godoc
//
//	@Summary		Get current account
//	@Description	Returns the authenticated user's account.
//	@Tags			accounts
//	@Produce		json
//	@Success		200	{object}	map[string]GetAccountResponse
//	@Failure		401	{object}	map[string]string
//	@Failure		404	{object}	map[string]string
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/accounts/me [get]
func GetMyAccount(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, jwtErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if jwtErr != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", jwtErr, env.SystemLogger)
			return
		}
		account, err := env.Database.GetUser(db.ByEmail(claims.Email))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		accountResponse := userToAccountResponse(account)
		err = writeResponse(w, accountResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// CreateAccount godoc
//
//	@Summary		Create account
//	@Description	Creates a new user account.
//	@Tags			accounts
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateAccountParams	true	"Create account payload"
//	@Success		201		{object}	map[string]CreateSuccessResponse
//	@Failure		400		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Router			/api/v1/accounts [post]
func CreateAccount(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var createAccountParams CreateAccountParams
		if err := json.NewDecoder(r.Body).Decode(&createAccountParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.SystemLogger)
			return
		}
		valid, err := createAccountParams.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %s", err).Error(), err, env.SystemLogger)
			return
		}
		// Force admin role for the first user in the system
		numUsers, err := env.Database.NumUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to check user count", err, env.SystemLogger)
			return
		}
		if numUsers == 0 {
			createAccountParams.RoleID = RoleID(db.RoleAdmin)
			env.SystemLogger.Info("First user in system — granting admin role",
				zap.String("email", createAccountParams.Email))
		}
		newUserID, err := env.Database.CreateUser(createAccountParams.Email, createAccountParams.Password, db.RoleID(createAccountParams.RoleID))
		if err != nil {
			if errors.Is(err, db.ErrAlreadyExists) {
				writeError(w, http.StatusBadRequest, "account with given email already exists", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		if env.AuthzRepository != nil {
			relation := RoleIDToRelation(db.RoleID(createAccountParams.RoleID))
			userID := authorization.UserID(createAccountParams.Email)
			if err := env.AuthzRepository.WriteTuple("system:notary", relation, userID); err != nil {
				env.SystemLogger.Error("Failed to write role tuple to OpenFGA", zap.Error(err), zap.String("user", userID), zap.String("relation", relation))
			}
		}

		var actor string
		claims, claimsErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if claimsErr == nil {
			actor = claims.Email
		}

		opts := []log.AuditOption{log.WithRequest(r)}
		if actor != "" {
			opts = append(opts, log.WithActor(actor))
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

// DeleteAccount godoc
//
//	@Summary		Delete account
//	@Description	Deletes the user account for the provided account ID.
//	@Tags			accounts
//	@Produce		json
//	@Param			id	path		int	true	"Account ID"
//	@Success		202	{object}	map[string]SuccessResponse
//	@Failure		400	{object}	map[string]string
//	@Failure		401	{object}	map[string]string
//	@Failure		404	{object}	map[string]string
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/accounts/{id} [delete]
func DeleteAccount(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idInt, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}
		account, err := env.Database.GetUser(db.ByUserID(idInt))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		numUsers, err := env.Database.NumUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		if numUsers <= 1 && env.AuthnRepository == nil {
			err = errors.New("cannot delete the last user account when OIDC is not enabled")
			writeError(w, http.StatusBadRequest, "cannot delete the last user account when OIDC is not enabled", err, env.SystemLogger)
			return
		}

		claims, err := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, env.SystemLogger)
			return
		}

		err = env.Database.DeleteUser(db.ByUserID(idInt))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		if env.AuthzRepository != nil {
			relation := RoleIDToRelation(account.RoleID)
			userID := authorization.UserID(account.Email)
			if err := env.AuthzRepository.DeleteTuple("system:notary", relation, userID); err != nil {
				env.SystemLogger.Error("Failed to delete role tuple from OpenFGA", zap.Error(err), zap.String("user", userID), zap.String("relation", relation))
			}
		}

		env.AuditLogger.UserDeleted(account.Email,
			log.WithActor(claims.Email),
			log.WithRequest(r),
		)

		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusAccepted)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// ChangeAccountPassword godoc
//
//	@Summary		Change account password
//	@Description	Changes the password for the provided account ID.
//	@Tags			accounts
//	@Accept			json
//	@Produce		json
//	@Param			id		path		int					true	"Account ID"
//	@Param			request	body		ChangeAccountParams	true	"Change password payload"
//	@Success		201		{object}	map[string]SuccessResponse
//	@Failure		400		{object}	map[string]string
//	@Failure		401		{object}	map[string]string
//	@Failure		404		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/accounts/{id}/change_password [post]
func ChangeAccountPassword(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var idNum int64
		idInt, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}
		idNum = idInt

		targetAccount, err := env.Database.GetUser(db.ByUserID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		claims, err := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
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
				log.WithActor(claims.Email),
				log.WithRequest(r),
				log.WithReason(err.Error()),
			)
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %s", err).Error(), err, env.SystemLogger)
			return
		}
		err = env.Database.UpdateUserPassword(db.ByUserID(idNum), changeAccountParams.Password)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				env.AuditLogger.PasswordChangeFailed(targetAccount.Email,
					log.WithActor(claims.Email),
					log.WithRequest(r),
					log.WithReason("user not found"),
				)
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			env.AuditLogger.PasswordChangeFailed(targetAccount.Email,
				log.WithActor(claims.Email),
				log.WithRequest(r),
				log.WithReason("database error"),
			)
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		env.AuditLogger.PasswordChanged(targetAccount.Email,
			log.WithActor(claims.Email),
			log.WithRequest(r),
		)
		env.AuditLogger.UserUpdated(targetAccount.Email, "password_change",
			log.WithActor(claims.Email),
			log.WithRequest(r),
		)

		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// ChangeMyPassword godoc
//
//	@Summary		Change current account password
//	@Description	Changes the password for the authenticated user.
//	@Tags			accounts
//	@Accept			json
//	@Produce		json
//	@Param			request	body		ChangeAccountParams	true	"Change password payload"
//	@Success		201		{object}	map[string]SuccessResponse
//	@Failure		400		{object}	map[string]string
//	@Failure		401		{object}	map[string]string
//	@Failure		404		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/accounts/me/change_password [post]
func ChangeMyPassword(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var idNum int64
		claims, err := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, env.SystemLogger)
			return
		}
		account, err := env.Database.GetUser(db.ByEmail(claims.Email))
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
				log.WithRequest(r),
				log.WithReason(err.Error()),
			)
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %s", err).Error(), err, env.SystemLogger)
			return
		}
		err = env.Database.UpdateUserPassword(db.ByUserID(idNum), changeAccountParams.Password)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				env.AuditLogger.PasswordChangeFailed(account.Email,
					log.WithRequest(r),
					log.WithReason("user not found"),
				)
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			env.AuditLogger.PasswordChangeFailed(account.Email,
				log.WithRequest(r),
				log.WithReason("database error"),
			)
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		env.AuditLogger.PasswordChanged(account.Email, log.WithRequest(r))
		env.AuditLogger.UserUpdated(account.Email, "password_change", log.WithRequest(r))

		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}
