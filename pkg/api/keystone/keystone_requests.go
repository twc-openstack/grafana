package keystone

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"fmt"
	"github.com/grafana/grafana/pkg/log"
	"github.com/grafana/grafana/pkg/setting"
)

///////////////////////
// Json Structs
///////////////////////

// Auth Request
type auth_request_struct struct {
	Auth auth_struct `json:"auth"`
}

type auth_struct struct {
	Identity auth_identity_struct `json:"identity"`
	Scope    string               `json:"scope,omitempty"`
}

type scoped_auth_token_request_struct struct {
	Auth scoped_auth_token_struct `json:"auth"`
}

type scoped_auth_password_request_struct struct {
	Auth scoped_auth_password_struct `json:"auth"`
}

type scoped_auth_token_struct struct {
	Identity auth_scoped_identity_struct `json:"identity"`
	Scope    auth_scope_struct           `json:"scope"`
}

type scoped_auth_password_struct struct {
	Identity auth_identity_struct `json:"identity"`
	Scope    auth_scope_struct    `json:"scope"`
}

type auth_scoped_identity_struct struct {
	Methods []string                 `json:"methods"`
	Token   auth_token_method_struct `json:"token"`
}

type auth_identity_struct struct {
	Methods  []string                    `json:"methods"`
	Password auth_password_method_struct `json:"password"`
}

type auth_token_method_struct struct {
	Id string `json:"id"`
}

type auth_password_method_struct struct {
	User auth_user_struct `json:"user"`
}

type auth_user_struct struct {
	Name     string                 `json:"name"`
	Password string                 `json:"password"`
	Domain   auth_userdomain_struct `json:"domain"`
}

type auth_userdomain_struct struct {
	Name string `json:"name"`
}

type auth_scope_struct struct {
	Project auth_project_struct `json:"project"`
}

type auth_project_struct struct {
	Name   string                     `json:"name"`
	Domain auth_project_domain_struct `json:"domain"`
}

type auth_project_domain_struct struct {
	Name string `json:"name"`
}

// Auth Response
type auth_response_struct struct {
	Token auth_token_struct `json:"token"`
}

type auth_token_struct struct {
	Roles      []auth_roles_struct       `json:"roles"`
	Expires_at string                    `json:"expires_at"`
	User       auth_user_response_struct `json:"user"`
}

type auth_roles_struct struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type auth_user_response_struct struct {
	Name   string                          `json:"name"`
	Id     string                          `json:"id"`
	Domain auth_userdomain_response_struct `json:"domain"`
}

type auth_userdomain_response_struct struct {
	Name string `json:"name"`
	Id   string `json:"id"`
}

// Projects Response
type project_response_struct struct {
	Projects []project_struct
}

type project_struct struct {
	Name     string
	Enabled  bool
	DomainId string `json:"domain_id"`
}

////////////////////////
// Keystone functions
////////////////////////

// Authentication Section Section
type Auth_data struct {
	Server        string
	Domain        string
	DomainId      string
	Username      string
	Password      string
	Project       string
	UnscopedToken string
	//response
	Token      string
	Expiration string
	Roles      []auth_roles_struct
}

func AuthenticateScoped(data *Auth_data) error {
	if data.UnscopedToken != "" {
		log.Trace("AuthenticateScoped() with token")
		var auth_post scoped_auth_token_request_struct
		auth_post.Auth.Identity.Methods = []string{"token"}
		auth_post.Auth.Identity.Token.Id = data.UnscopedToken
		auth_post.Auth.Scope.Project.Domain.Name = data.Domain
		auth_post.Auth.Scope.Project.Name = data.Project
		b, _ := json.Marshal(auth_post)
		return authenticate(data, b)
	} else {
		var auth_post scoped_auth_password_request_struct
		log.Trace("AuthenticateScoped() with password")
		auth_post.Auth.Identity.Methods = []string{"password"}
		auth_post.Auth.Identity.Password.User.Name = data.Username
		auth_post.Auth.Identity.Password.User.Password = data.Password
		auth_post.Auth.Identity.Password.User.Domain.Name = data.Domain
		auth_post.Auth.Scope.Project.Domain.Name = data.Domain
		auth_post.Auth.Scope.Project.Name = data.Project
		b, _ := json.Marshal(auth_post)
		return authenticate(data, b)
	}
}

func AuthenticateUnscoped(data *Auth_data) error {
	log.Trace("AuthenticateUnscoped()")
	var auth_post auth_request_struct
	auth_post.Auth.Scope = "unscoped"
	auth_post.Auth.Identity.Methods = []string{"password"}
	auth_post.Auth.Identity.Password.User.Name = data.Username
	auth_post.Auth.Identity.Password.User.Password = data.Password
	auth_post.Auth.Identity.Password.User.Domain.Name = data.Domain
	b, _ := json.Marshal(auth_post)

	return authenticate(data, b)
}
func authenticate(data *Auth_data, b []byte) error {
	auth_url := data.Server + "/v3/auth/tokens?nocatalog"

	log.Debug("Authentication request to URL: %s", auth_url)

	log.Debug("Authentication request body: \n%s", anonymisePasswordsTokens(data, b))

	request, err := http.NewRequest("POST", auth_url, bytes.NewBuffer(b))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "application/json")

	resp, err := GetHttpClient().Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		return errors.New("Keystone authentication failed: " + resp.Status)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	strBody := buf.Bytes()
	log.Debug("Authentication response: \n%s", strBody)

	bodyReader := bytes.NewBufferString(fmt.Sprintf("%s", strBody))
	var decoder = json.NewDecoder(bodyReader)

	var auth_response auth_response_struct
	err = decoder.Decode(&auth_response)
	if err != nil {
		return err
	}

	data.Token = resp.Header.Get("X-Subject-Token")
	data.Expiration = auth_response.Token.Expires_at
	data.Roles = auth_response.Token.Roles
	data.DomainId = auth_response.Token.User.Domain.Id

	return nil
}

func anonymisePasswordsTokens(data *Auth_data, json []byte) []byte {
	anonJson := json
	if data.Password != "" {
		anonJson = bytes.Replace(anonJson, []byte("\"password\":\""+data.Password+"\""),
			[]byte("\"password\":\"********\""), -1)
	}
	if data.UnscopedToken != "" {
		anonJson = bytes.Replace(anonJson, []byte("\"token\":{\"id\":\""+data.UnscopedToken+"\""),
			[]byte("\"token\":{\"id\":\"****************\""), -1)
	}

	return anonJson
}

// Projects Section
type Projects_data struct {
	Token    string
	Server   string
	DomainId string
	//response
	Projects []string
}

func GetProjects(data *Projects_data) error {
	log.Info("Authentication request to URL: %s", data.Server+"/v3/auth/projects")

	request, err := http.NewRequest("GET", data.Server+"/v3/auth/projects", nil)
	if err != nil {
		return err
	}
	request.Header.Add("X-Auth-Token", data.Token)

	resp, err := GetHttpClient().Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New("Keystone project-list failed: " + resp.Status)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	strBody := buf.Bytes()
	log.Debug("Projects response: \n%s", strBody)

	bodyReader := bytes.NewBufferString(fmt.Sprintf("%s", strBody))
	var decoder = json.NewDecoder(bodyReader)

	var project_response project_response_struct
	err = decoder.Decode(&project_response)
	if err != nil {
		return err
	}
	for _, project := range project_response.Projects {
		if project.Enabled && (project.DomainId == data.DomainId) {
			data.Projects = append(data.Projects, project.Name)
		}
	}
	return nil
}

// From https://golang.org/pkg/net/http:
// "Clients and Transports are safe for concurrent use by multiple goroutines and for efficiency should only be created once and re-used."
var client *http.Client

func GetHttpClient() *http.Client {
	if client != nil {
		return client
	} else {
		var certPool *x509.CertPool
		if pemfile := setting.KeystoneRootCAPEMFile; pemfile != "" {
			certPool = x509.NewCertPool()
			pemFileContent, err := ioutil.ReadFile(pemfile)
			if err != nil {
				panic(err)
			}
			if !certPool.AppendCertsFromPEM(pemFileContent) {
				log.Error(3, "Failed to load any certificates from Root CA PEM file %s", pemfile)
			} else {
				log.Info("Successfully loaded certificate(s) from %s", pemfile)
			}
		}
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool,
				InsecureSkipVerify: !setting.KeystoneVerifySSLCert},
		}
		tr.Proxy = http.ProxyFromEnvironment

		client = &http.Client{Transport: tr}
		return client
	}
}
