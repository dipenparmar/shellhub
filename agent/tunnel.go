package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

type Tunnel struct {
	router       *mux.Router
	connHandler  func(w http.ResponseWriter, r *http.Request)
	closeHandler func(w http.ResponseWriter, r *http.Request)
}

func NewTunnel() *Tunnel {
	t := &Tunnel{
		router: mux.NewRouter(),
		connHandler: func(w http.ResponseWriter, r *http.Request) {
			panic("connHandler can not be nil")
		},
		closeHandler: func(w http.ResponseWriter, r *http.Request) {
			panic("closeHandler can not be nil")
		},
	}
	t.router.HandleFunc("/ssh/{id}", t.connHandler)
	t.router.HandleFunc("/ssh/close/{id}", t.closeHandler).Methods("DELETE")
}
