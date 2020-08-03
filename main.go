package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

type VaultCredentialsResponse struct {
	LeaseId string `json:"lease_id"`
	Data    struct {
		AccessKey     string  `json:"access_key"`
		SecretKey     string  `json:"secret_key"`
		SecurityToken *string `json:"security_token"`
	} `json:"data"`
}

type SecurityCredentialsResponse struct {
	Code            string
	Type            string
	AccessKeyId     string
	SecretAccessKey string
	Token           *string
}

type Config struct {
	bindAddr      string
	vaultRoleName string
	vaultServer   string
	vaultToken    string
}

func (c *Config) Validate() {
	if c.vaultRoleName == "" {
		log.Fatal("Vault role name is empty")
	}

	if c.vaultToken == "" {
		log.Fatal("Vault access token is empty")
	}

	if c.vaultServer == "" {
		log.Fatal("Vault server address is empty")
	}
}

var (
	config *Config
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func loadCredentialsFromVault() (*SecurityCredentialsResponse, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/aws/creds/%s", config.vaultServer, config.vaultRoleName), nil)

	if err != nil {
		return nil, err
	}

	req.Header.Add("X-Vault-Token", config.vaultToken)

	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	credentials := VaultCredentialsResponse{}

	err = json.Unmarshal(body, &credentials)

	if err != nil {
		return nil, err
	}

	log.WithField("lease_id", credentials.LeaseId).Info("leased AWS credentials from Vault")

	return &SecurityCredentialsResponse{
		Code:            "Success",
		Type:            "AWS-HMAC",
		AccessKeyId:     credentials.Data.AccessKey,
		SecretAccessKey: credentials.Data.SecretKey,
		Token:           credentials.Data.SecurityToken,
	}, nil
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

	resp, err := loadCredentialsFromVault()

	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("failed to load AWS credentials from Vault")

		w.WriteHeader(http.StatusInternalServerError)

		return
	}

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

	flag.StringVar(&config.bindAddr, "bind", "127.0.0.1:3456", "Bind address")
	flag.StringVar(&config.vaultRoleName, "role", "", "Vault role name")
	flag.StringVar(&config.vaultServer, "vault", "", "Vault server address")
	flag.StringVar(&config.vaultToken, "token", "", "Vault access token")

	flag.Parse()
	config.Validate()

	http.HandleFunc("/", handleHttpRequest)

	err := http.ListenAndServe(config.bindAddr, nil)

	if err != nil {
		log.Error(err)
	}
}
