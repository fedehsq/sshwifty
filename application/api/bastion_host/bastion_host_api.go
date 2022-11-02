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

func (t *Token) String() string {
	return fmt.Sprintf("client_token: %s, jwt: %s", t.Auth.ClientToken, t.Auth.Jwt.Token)
}

func SignIn() (*Token, error) {
	rb, err := json.Marshal(map[string]string{
		"username": config.Conf.Username,
		"password": config.Conf.Password,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/auth/auth-plugin/admin-login", config.Conf.VaultAddress), strings.NewReader(string(rb)))
	if err != nil {
		return nil, err
	}
	body, err := doRequest(req)
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

func doRequest(req *http.Request) ([]byte, error) {
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
