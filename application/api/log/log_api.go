package logapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	bastionhostapi "github.com/nirui/sshwifty/application/api/bastion_host"
	"github.com/nirui/sshwifty/config"
)

type LogRequest struct {
	Command string `json:"command"`
	SshAddress string `json:"ssh_address"`
	Username string `json:"username"`
}

func Create(log LogRequest) error {
	rb, err := json.Marshal(log)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/auth/auth-plugin/logs", config.Conf.VaultAddress), strings.NewReader(string(rb)))
	if err != nil {
		return err
	}
	_, err = doRequest(req, bastionhostapi.BhTokens.Auth.ClientToken)
	if err != nil {
		return err
	}
	return nil
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
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("status: %d, body: %s", res.StatusCode, body)
	}
	return body, err
}
