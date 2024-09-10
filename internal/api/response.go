package server

import (
	"fmt"
	"log"
	"net/http"
)

// logErrorAndWriteResponse is a helper function that logs any error and writes it back as an http response
func logErrorAndWriteResponse(msg string, status int, w http.ResponseWriter) {
	errMsg := fmt.Sprintf("error: %s", msg)
	log.Println(errMsg)
	w.WriteHeader(status)
	if _, err := w.Write([]byte(errMsg)); err != nil {
		log.Printf("error writing response: %s", err.Error())
	}
}
