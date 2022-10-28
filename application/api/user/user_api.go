package userapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"github.com/nirui/sshwifty/application/api/bastion_host"
	"github.com/nirui/sshwifty/config"
)

type UserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
		Metadata    struct {
			Username string `json:"username"`
			Host     string `json:"host"`
		} `json:"metadata"`
	} `json:"auth"`
}

type SshOtp struct {
	Data struct {
		Key      string `json:"key"`
		Ip       string `json:"ip"`
		Port     int    `json:"port"`
		Username string `json:"username"`
	} `json:"data"`
}

func (u *UserRequest) signin(bhToken string, jwt string) (*UserResponse, error) {
	// User authentication with vault: as authorizion header pass the vault token and jwt
	rb, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/auth/auth-plugin/user-login", config.Conf.VaultAddress), strings.NewReader(string(rb)))
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	body, err := doRequest(req, bhToken, jwt)
	if err != nil {
		return nil, err
	}
	user := &UserResponse{}
	err = json.Unmarshal(body, &user)
	if err != nil {
		return nil, err
	}
	return user, err
}

func (u *UserResponse) getSshOtp() (*SshOtp, error) {
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/ssh/creds/otp_key_role", config.Conf.VaultAddress), strings.NewReader(fmt.Sprintf(`{"ip":"%s"}`, u.Auth.Metadata.Host)))
	if err != nil {
		return nil, err
	}
	body, err := doRequest(req, u.Auth.ClientToken, "")
	if err != nil {
		return nil, err
	}
	sshOTP := &SshOtp{}
	err = json.Unmarshal(body, &sshOTP)
	if err != nil {
		return nil, err
	}
	return sshOTP, err
}

func Signin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var userReq UserRequest
	err := json.NewDecoder(r.Body).Decode(&userReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Bastion host authentication with vault
	bh, err := bastionhostapi.SignIn()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// User authentication with vault
	user, err := userReq.signin(bh.Auth.ClientToken, bh.Auth.Jwt.Token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// User has now the token to request the SSH OTP: request the SSH OTP
	sshOtp, err := user.getSshOtp()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(sshOtp)
}

func doRequest(req *http.Request, vaultToken string, JWT string) ([]byte, error) {
	req.Header.Set("X-Vault-Token", vaultToken)
	req.Header.Set("Authorization", JWT)

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
