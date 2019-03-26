package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
)

const envPrefix = "SECRET_"

var (
	vaultAddr     = flag.String("h", "http://localhost:8200", "Vault address")
	vaultToken    = flag.String("k", "", "Vault token")
	kubeToken     = flag.String("t", "", "Kubernetes token")
	vaultKubeRole = flag.String("r", "", "Vault kubernetes role")
	debugMode     = flag.Bool("d", false, "Debug mode")
)

type KubeLoginData struct {
	Jwt  string `json:"jwt"`
	Role string `json:"role"`
}

type Auth struct {
	Client_token   string   `json:"client_token"`
	Accessor       string   `json:"accessor"`
	Policies       []string `json:"policies"`
	Token_policies []string `json:"token_policies"`
	Metadata       map[string]string
	Lease_duration int    `json:"lease_duration"`
	Renewable      bool   `json:"bool"`
	Entity_id      string `json:"entity_id"`
	Token_type     string `json:"token_type"`
}

type SecretData struct {
	Data     map[string]string `json:"data"`
	Metadata map[string]string `json:"metadata"`
}

type VaultResponse struct {
	Request_id     string     `json:"request_id"`
	Lease_id       string     `json:"lease_id"`
	Renewable      bool       `json:"renewable"`
	Lease_duration int        `json:"lease_duration"`
	SecretData     SecretData `json:"data,omitempty"`
	Wrap_info      string     `json:"wrap_info"`
	Warnings       string     `json:"warnings"`
	Auth           Auth       `json:"auth,omitempty"`
}

type Secrets struct {
	key   string
	value string
}

func main() {
	flag.Parse()

	if *vaultToken == "" {
		logInfo(fmt.Sprintf("Logging in to Vault: %s", *vaultAddr))
		param := &KubeLoginData{
			Jwt:  *kubeToken,
			Role: *vaultKubeRole,
		}
		resp := vaultKubernetesLogin(param)
		vaultToken = &resp.Auth.Client_token
	}

	secrets := getTargetSecrets(envPrefix)

	for _, value := range vaultRetrieveSecrets(secrets) {
		fmt.Printf("\nexport %v=%v", value.key, value.value)
	}
}

func vaultRetrieveSecrets(secrets []Secrets) (values []Secrets) {
	for _, secret := range secrets {
		p := strings.Split(secret.value, "/")
		rootPath, subPath := p[0], strings.Join(p[1:], "/")

		url := fmt.Sprintf("%s/v1/%s/data/%s", *vaultAddr, rootPath, subPath)
		req, err := http.NewRequest("GET", url, nil)
		req.Header.Set("X-Vault-Token", *vaultToken)
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()

		r := VaultResponse{}
		body, _ := ioutil.ReadAll(resp.Body)
		json.Unmarshal(body, &r)

		values = append(values,
			Secrets{
				key:   secret.key,
				value: r.SecretData.Data[strings.ToLower(secret.key)],
			},
		)
	}

	return
}

func vaultKubernetesLogin(param *KubeLoginData) (r VaultResponse) {
	b, _ := json.Marshal(param)
	req, err := http.NewRequest("POST", *vaultAddr+"/v1/auth/kubernetes/login", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, &r)

	if resp.StatusCode != 200 {
		fmt.Printf("\nError occurred: %s", body)
	}

	return
}

func getTargetSecrets(prefix string) (secrets []Secrets) {
	for _, e := range os.Environ() {
		kv := strings.Split(e, "=")

		matched, _ := regexp.MatchString(fmt.Sprintf("%s.*", prefix), kv[0])
		if !matched {
			continue
		}

		secrets = append(secrets, Secrets{key: kv[0][len(prefix):len(kv[0])], value: kv[1]})
	}
	return
}

func logInfo(message string) {
	if !*debugMode {
		return
	}
	fmt.Printf("\n%s", message)
}
