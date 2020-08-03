package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

type SecurityCredentialsResponse struct {
	Code string
}

type Config struct {
	bindAddr string
	vaultRoleName string
}

func (c *Config) Validate() {
	if c.vaultRoleName == "" {
		log.Fatal("Vault role name is empty")
	}
}

var (
	config *Config
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func handleHttpRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain")
	w.Header().Add("Accept-Ranges", "none")
	w.Header().Add("Server", "EC2ws")
	w.Header().Add("Connection", "close")

	if !strings.HasPrefix(r.URL.Path, "/latest/meta-data/iam/security-credentials") {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	requestedRole := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/latest/meta-data/iam/security-credentials"), "/")

	if requestedRole == "" {
		_, err := w.Write([]byte(config.vaultRoleName))

		if err != nil {
			log.Error(err)
		}

		return
	}

	if requestedRole != config.vaultRoleName {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	resp := &SecurityCredentialsResponse{Code: "Success"}

	encoded, err := json.Marshal(resp)

	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("failed to encode JSON response")

		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	_, err = w.Write(encoded)

	if err != nil {
		log.Error(err)
	}
}

func main() {
	config = &Config{}

	flag.StringVar(&config.vaultRoleName, "role", "", "Vault role name")
	flag.StringVar(&config.bindAddr, "bind", "127.0.0.1:3456", "Bind address")

	flag.Parse()
	config.Validate()

	http.HandleFunc("/", handleHttpRequest)

	err := http.ListenAndServe(config.bindAddr, nil)

	if err != nil {
		log.Error(err)
	}
}
