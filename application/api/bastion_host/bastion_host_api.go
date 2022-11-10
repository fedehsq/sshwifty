package bastionhostapi

import (
	"encoding/json"
	"fmt"
	"github.com/nirui/sshwifty/config"
	"io"
	"net/http"
	"strings"
)

type Token struct {
	Auth struct {
		ClientToken string `json:"client_token"`
		Jwt         struct {
			Token string `json:"jwt"`
		} `json:"metadata"`
	} `json:"auth"`
}

type Credentials struct {
	Data struct {
		Data struct {
			Password string `json:"password"`
			Username string `json:"username"`
		} `json:"data"`
	} `json:"data"`
} 

func (t *Token) String() string {
	return fmt.Sprintf("client_token: %s, jwt: %s", t.Auth.ClientToken, t.Auth.Jwt.Token)
}

// Get the credentials from the vault of the bastion host
func getCredentials(token string) (*Credentials, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/secret/data/bastion", config.Conf.VaultAddress), nil)
	if err != nil {
		return nil, err
	}
	body, err := doRequest(req, token)
	if err != nil {
		return nil, err
	}
	credentials := Credentials{}
	err = json.Unmarshal(body, &credentials)
	if err != nil {
		return nil, err
	}
	return &credentials, nil
}

// Bastion host authentication with vault
func SignIn() (*Token, error) {
	credentials, err := getCredentials(config.Conf.Token)
	if err != nil {
		return nil, err
	}
	rb, err := json.Marshal(credentials.Data.Data)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/auth/auth-plugin/admin/signin", config.Conf.VaultAddress), strings.NewReader(string(rb)))
	if err != nil {
		return nil, err
	}
	body, err := doRequest(req, "")
	if err != nil {
		return nil, err
	}
	tokens := Token{}
	err = json.Unmarshal(body, &tokens)
	if err != nil {
		return nil, err
	}
	return &tokens, nil
}

func doRequest(req *http.Request, vaultToken string) ([]byte, error) {
	req.Header.Set("X-Vault-Token", vaultToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %d, body: %s", res.StatusCode, body)
	}
	return body, err
}
