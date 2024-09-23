package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// writeError is a helper function that logs any error and writes it back as an http response
func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	type errorResponse struct {
		Error string `json:"error"`
	}

	errorMessage := fmt.Sprintf(format, args...)
	log.Println(errorMessage)

	resp := errorResponse{Error: errorMessage}
	respBytes, err := json.Marshal(&resp)
	if err != nil {
		log.Printf("Error marshalling error response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	_, err = w.Write(respBytes)
	if err != nil {
		log.Printf("Error writing error response: %v", err)
	}
}
