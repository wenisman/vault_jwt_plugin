package lib

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

// Server - the HTTP server that will contain the logic for the JWT
type Server struct {
	Router *mux.Router
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func (s *Server) issueJwt(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	role := vars["role"]
	claim := vars["claim"]

	client := &http.Client{}
	jwt, err := IssueJwt(client, role, claim)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Unable to issue JWT")
		return
	}

	respondWithJSON(w, http.StatusOK, jwt)
}

func (s *Server) validateJwt(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	jwt := vars["token"]

	client := &http.Client{}
	isValid, err := ValidateJWT(client, jwt)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Unable to validate provided JWT")
		return
	}

	respondWithJSON(w, http.StatusOK, isValid)
}

func (s *Server) initialiseRoutes() {
	s.Router.HandleFunc("/issue/{role}", s.issueJwt).Methods("GET")
	s.Router.HandleFunc("/issue/{role}/{claim}", s.issueJwt).Methods("GET")
	s.Router.HandleFunc("/validate/{token}", s.validateJwt).Methods("GET")
}

// Run - start the server
func (s *Server) Run() {
	s.Router = mux.NewRouter()
	s.initialiseRoutes()
	http.ListenAndServe(":8000", s.Router)
}
