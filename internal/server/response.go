package server

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

type APIResponse struct {
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

// writeResponse is a helper function that writes a standardized JSON response to the http.ResponseWriter.
// The status is an HTTP status that is mandatory.
// The message is optional and can be used for both success and error responses.
func writeResponse(w http.ResponseWriter, status int, message string, data any, logger *zap.Logger) {
	resp := APIResponse{
		Message: message,
		Data:    data,
	}
	logger.Info("API response: ", zap.Int("status", status), zap.String("message", message), zap.Any("data", data))

	respBytes, err := json.Marshal(&resp)
	if err != nil {
		logger.Error("error marshalling response", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if _, err := w.Write(respBytes); err != nil {
		logger.Error("error writing response", zap.Error(err))
	}
}
