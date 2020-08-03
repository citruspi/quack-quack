package main

import (
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func handleHttpRequest(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/latest/meta-data/iam/security-credentials") {
		w.WriteHeader(http.StatusNotFound)
	}

	_, err := w.Write([]byte("hello world"))

	if err != nil {
		log.Error(err)
	}
}


func main() {
	http.HandleFunc("/", handleHttpRequest)

	err := http.ListenAndServe("127.0.0.1:3456", nil)

	if err != nil {
		log.Error(err)
	}
}
