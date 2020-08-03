package main

import (
	"flag"
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

type Config struct {
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
	if !strings.HasPrefix(r.URL.Path, "/latest/meta-data/iam/security-credentials") {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	resp := ""
	requestedRole := strings.TrimPrefix(r.URL.Path, "/latest/meta-data/iam/security-credentials")

	if requestedRole == "" || requestedRole == "/" {
		resp = config.vaultRoleName
	}

	_, err := w.Write([]byte(resp))

	if err != nil {
		log.Error(err)
	}
}


func main() {
	config = &Config{}

	flag.StringVar(&config.vaultRoleName, "role", "", "Vault role name")

	flag.Parse()
	config.Validate()

	http.HandleFunc("/", handleHttpRequest)

	err := http.ListenAndServe("127.0.0.1:3456", nil)

	if err != nil {
		log.Error(err)
	}
}
