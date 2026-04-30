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

type UpdateAccountRoleParams struct {
	RoleID RoleID `json:"role_id"`
}

func (params *UpdateAccountRoleParams) IsValid() (bool, error) {
	if !params.RoleID.IsValid() {
		return false, fmt.Errorf("invalid role ID: %d", params.RoleID)
	}
	return true, nil
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

// ListAccounts returns all accounts from the database
func ListAccounts(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accounts, err := env.Database.ListUsers()
		if err != nil {
			env.SystemLogger.Error("failed to list users", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		accountsResponse := make([]GetAccountResponse, len(accounts))
		for i, account := range accounts {
			accountsResponse[i] = userToAccountResponse(&account)
		}
		writeResponse(w, http.StatusOK, "", accountsResponse, env.SystemLogger)
	}
}

// GetAccount receives an id as a path parameter, and
// returns the corresponding User Account
// It can only return accounts that exist in the database
// If the account was logged in with OIDC, it will only return the email
func GetAccount(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var account *db.User
		var err error
		if id == "me" {
			claims, jwtErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
			if jwtErr != nil {
				env.SystemLogger.Error("failed to get JWT claims from cookie", zap.Error(jwtErr))
				writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
				return
			}
			account = &db.User{
				Email: claims.Email,
			}
		} else {
			var idNum int64
			idNum, err = strconv.ParseInt(id, 10, 64)
			if err != nil {
				writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
				return
			}
			account, err = env.Database.GetUser(db.ByUserID(idNum))
		}
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to get user", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		accountResponse := userToAccountResponse(account)
		writeResponse(w, http.StatusOK, "", accountResponse, env.SystemLogger)
	}
}

// GetMyAccount receives "me" as a path parameter, and
// returns the corresponding User Account. Unlike GetAccount,
// it uses the JWT claims to retrieve the account information.
func GetMyAccount(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, jwtErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if jwtErr != nil {
			env.SystemLogger.Error("failed to get JWT claims from cookie", zap.Error(jwtErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}
		account, err := env.Database.GetUser(db.ByEmail(claims.Email))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to get current user", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		accountResponse := userToAccountResponse(account)
		writeResponse(w, http.StatusOK, "", accountResponse, env.SystemLogger)
	}
}

// CreateAccount creates a new Account, and returns the id of the created row
func CreateAccount(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var createAccountParams CreateAccountParams
		if err := json.NewDecoder(r.Body).Decode(&createAccountParams); err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}
		valid, err := createAccountParams.IsValid()
		if !valid {
			writeResponse(w, http.StatusBadRequest, err.Error(), nil, env.SystemLogger)
			return
		}
		// Force admin role for the first user in the system
		numUsers, err := env.Database.NumUsers()
		if err != nil {
			env.SystemLogger.Error("failed to check user count", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
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
				writeResponse(w, http.StatusBadRequest, "account with given email already exists", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to create user", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
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

		writeResponse(w, http.StatusCreated, "", map[string]int64{"id": newUserID}, env.SystemLogger)
	}
}

// DeleteAccount handler receives an id as a path parameter,
// deletes the corresponding User Account, and returns a http.StatusNoContent on success
func DeleteAccount(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idInt, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}
		account, err := env.Database.GetUser(db.ByUserID(idInt))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to get user for deletion", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		numUsers, err := env.Database.NumUsers()
		if err != nil {
			env.SystemLogger.Error("failed to count users", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		if numUsers <= 1 && env.AuthnRepository == nil {
			writeResponse(w, http.StatusBadRequest, "cannot delete the last user account when OIDC is not enabled", nil, env.SystemLogger)
			return
		}

		claims, err := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if err != nil {
			env.SystemLogger.Error("failed to get JWT claims from cookie", zap.Error(err))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		err = env.Database.DeleteUser(db.ByUserID(idInt))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to delete user", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
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

		writeResponse(w, http.StatusAccepted, "", nil, env.SystemLogger)
	}
}

func ChangeAccountPassword(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var idNum int64
		idInt, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}
		idNum = idInt

		targetAccount, err := env.Database.GetUser(db.ByUserID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to get target user for password change", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		claims, err := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if err != nil {
			env.SystemLogger.Error("failed to get JWT claims from cookie", zap.Error(err))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		var changeAccountParams ChangeAccountParams
		if err := json.NewDecoder(r.Body).Decode(&changeAccountParams); err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}
		valid, err := changeAccountParams.IsValid()
		if !valid {
			env.AuditLogger.PasswordChangeFailed(targetAccount.Email,
				log.WithActor(claims.Email),
				log.WithRequest(r),
				log.WithReason(err.Error()),
			)
			writeResponse(w, http.StatusBadRequest, err.Error(), nil, env.SystemLogger)
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
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.AuditLogger.PasswordChangeFailed(targetAccount.Email,
				log.WithActor(claims.Email),
				log.WithRequest(r),
				log.WithReason("database error"),
			)
			env.SystemLogger.Error("failed to update user password", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
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

		writeResponse(w, http.StatusCreated, "", nil, env.SystemLogger)
	}
}

func ChangeMyPassword(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var idNum int64
		claims, err := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if err != nil {
			env.SystemLogger.Error("failed to get JWT claims from cookie", zap.Error(err))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}
		account, err := env.Database.GetUser(db.ByEmail(claims.Email))
		if err != nil {
			env.SystemLogger.Error("failed to get current user for password change", zap.Error(err))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}
		idNum = account.ID
		var changeAccountParams ChangeAccountParams
		if err := json.NewDecoder(r.Body).Decode(&changeAccountParams); err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}
		valid, err := changeAccountParams.IsValid()
		if !valid {
			env.AuditLogger.PasswordChangeFailed(account.Email,
				log.WithRequest(r),
				log.WithReason(err.Error()),
			)
			writeResponse(w, http.StatusBadRequest, err.Error(), nil, env.SystemLogger)
			return
		}
		err = env.Database.UpdateUserPassword(db.ByUserID(idNum), changeAccountParams.Password)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				env.AuditLogger.PasswordChangeFailed(account.Email,
					log.WithRequest(r),
					log.WithReason("user not found"),
				)
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.AuditLogger.PasswordChangeFailed(account.Email,
				log.WithRequest(r),
				log.WithReason("database error"),
			)
			env.SystemLogger.Error("failed to update current user password", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		env.AuditLogger.PasswordChanged(account.Email, log.WithRequest(r))
		env.AuditLogger.UserUpdated(account.Email, "password_change", log.WithRequest(r))

		writeResponse(w, http.StatusCreated, "", nil, env.SystemLogger)
	}
}

// UpdateAccountRole updates an existing account's role.
func UpdateAccountRole(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if err != nil {
			writeResponse(w, http.StatusUnauthorized, "Unauthorized", err, env.SystemLogger)
			return
		}
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", err, env.SystemLogger)
			return
		}

		account, err := env.Database.GetUser(db.ByUserID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "", nil, env.SystemLogger)
				return
			}
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		if idNum == 1 {
			err = errors.New("updating the default admin account role is not allowed")
			writeResponse(w, http.StatusBadRequest, "updating the default admin account role is not allowed.", err, env.SystemLogger)
			return
		}

		var params UpdateAccountRoleParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			writeResponse(w, http.StatusBadRequest, "Invalid JSON format", err, env.SystemLogger)
			return
		}
		valid, err := params.IsValid()
		if !valid {
			writeResponse(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %s", err), err, env.SystemLogger)
			return
		}

		if err := env.Database.UpdateUserRole(db.ByUserID(idNum), db.RoleID(params.RoleID)); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeResponse(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		env.AuditLogger.UserUpdated(account.Email, "role_change",
			log.WithActor(claims.Email),
			log.WithRequest(r),
		)
		writeResponse(w, http.StatusCreated, "", nil, env.SystemLogger)
	}
}
