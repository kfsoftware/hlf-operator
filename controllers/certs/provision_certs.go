package certs

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	mspprov "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	fabricctx "github.com/hyperledger/fabric-sdk-go/pkg/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite/bccsp/sw"
	fabImpl "github.com/hyperledger/fabric-sdk-go/pkg/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/msp/api"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"gopkg.in/yaml.v2"
)

type FabricPem struct {
	Pem string `yaml:"pem"`
}
type FabricMultiplePem struct {
	Pem []string `yaml:"pem"`
}
type FabricConfigUser struct {
	Key  FabricPem `yaml:"key"`
	Cert FabricPem `yaml:"cert"`
}
type FabricHttpOptions struct {
	Verify bool `yaml:"verify"`
}
type FabricCryptoStore struct {
	Path string `yaml:"path"`
}
type FabricCredentialStore struct {
	Path        string            `yaml:"path"`
	CryptoStore FabricCryptoStore `yaml:"cryptoStore"`
}
type FabricConfigOrg struct {
	Mspid                  string                      `yaml:"mspid"`
	CryptoPath             string                      `yaml:"cryptoPath"`
	Users                  map[string]FabricConfigUser `yaml:"users,omitempty"`
	CredentialStore        FabricCredentialStore       `yaml:"credentialStore,omitempty"`
	CertificateAuthorities []string                    `yaml:"certificateAuthorities"`
}
type FabricRegistrar struct {
	EnrollID     string `yaml:"enrollId"`
	EnrollSecret string `yaml:"enrollSecret"`
}
type FabricConfigCA struct {
	URL         string            `yaml:"url"`
	CaName      string            `yaml:"caName"`
	TLSCACerts  FabricMultiplePem `yaml:"tlsCACerts"`
	Registrar   FabricRegistrar   `yaml:"registrar"`
	HTTPOptions FabricHttpOptions `yaml:"httpOptions"`
}
type FabricConfigTimeoutParams struct {
	Endorser string `yaml:"endorser"`
}
type FabricConfigTimeout struct {
	Peer FabricConfigTimeoutParams `yaml:"peer"`
}
type FabricConfigConnection struct {
	Timeout FabricConfigTimeout `yaml:"timeout"`
}
type FabricConfigClient struct {
	Organization    string                 `yaml:"organization"`
	CredentialStore FabricCredentialStore  `yaml:"credentialStore,omitempty"`
	Connection      FabricConfigConnection `yaml:"connection"`
}
type FabricConfig struct {
	Name                   string                     `yaml:"name"`
	Version                string                     `yaml:"version"`
	Client                 FabricConfigClient         `yaml:"client"`
	Organizations          map[string]FabricConfigOrg `yaml:"organizations"`
	CertificateAuthorities map[string]FabricConfigCA  `yaml:"certificateAuthorities"`
}

type FabricCAParams struct {
	TLSCert      string
	URL          string
	Name         string
	MSPID        string
	EnrollID     string
	EnrollSecret string
}

func getFabricConfig(params FabricCAParams) (*FabricConfig, error) {
	caPem := params.TLSCert
	caUrl := params.URL
	caName := params.Name
	mspID := params.MSPID
	fabricConfig := &FabricConfig{
		Name:    "test-network-org1",
		Version: "1.0.0",
		Client: FabricConfigClient{
			Organization: mspID,
			Connection: FabricConfigConnection{
				Timeout: FabricConfigTimeout{
					Peer: FabricConfigTimeoutParams{
						Endorser: "300",
					},
				},
			},
		},
		Organizations: map[string]FabricConfigOrg{
			mspID: {
				CryptoPath: "/tmp/cryptopath",
				Mspid:      mspID,
				CredentialStore: FabricCredentialStore{
					Path:        "./credentials",
					CryptoStore: FabricCryptoStore{Path: "./crypto-store"},
				},
				CertificateAuthorities: []string{
					"ca.org1.example.com",
				},
			},
		},
		CertificateAuthorities: map[string]FabricConfigCA{
			"ca.org1.example.com": {
				URL:    caUrl,
				CaName: caName,
				TLSCACerts: FabricMultiplePem{
					Pem: []string{caPem},
				},
				Registrar: FabricRegistrar{
					EnrollID:     params.EnrollID,
					EnrollSecret: params.EnrollSecret,
				},
				HTTPOptions: FabricHttpOptions{Verify: false},
			},
		},
	}

	return fabricConfig, nil
}

type EnrollUserRequest struct {
	TLSCert    string
	URL        string
	Name       string
	MSPID      string
	User       string
	Secret     string
	Hosts      []string
	CN         string
	Profile    string
	Attributes []*api.AttributeRequest
}
type GetCAInfoRequest struct {
	TLSCert string
	URL     string
	Name    string
	MSPID   string
}

type RegisterUserRequest struct {
	TLSCert      string
	URL          string
	Name         string
	MSPID        string
	EnrollID     string
	EnrollSecret string
	User         string
	Secret       string
	Type         string
	Attributes   []api.Attribute
}

const (
	keyStorePath = "/tmp/hlf-operator"
)

func RegisterUser(params RegisterUserRequest) (string, error) {
	caClient, _, _, _, err := GetClient(FabricCAParams{
		TLSCert:      params.TLSCert,
		URL:          params.URL,
		Name:         params.Name,
		MSPID:        params.MSPID,
		EnrollID:     params.EnrollID,
		EnrollSecret: params.EnrollSecret,
	}, keyStorePath)
	if err != nil {
		return "", err
	}

	secret, err := caClient.Register(&api.RegistrationRequest{
		Name:           params.User,
		Type:           params.Type,
		MaxEnrollments: -1,
		Affiliation:    "",
		Attributes:     params.Attributes,
		CAName:         params.Name,
		Secret:         params.Secret,
	})
	if err != nil {
		return "", err
	}
	return secret, nil
}

func GetCAInfo(params GetCAInfoRequest) (*api.GetCAInfoResponse, error) {
	keystorePath, err := ioutil.TempDir("", "enroll")
	if err != nil {
		return nil, err
	}
	caClient, _, _, _, err := GetClient(FabricCAParams{
		TLSCert: params.TLSCert,
		URL:     params.URL,
		Name:    params.Name,
		MSPID:   params.MSPID,
	}, keystorePath)
	if err != nil {
		return nil, err
	}
	caInfo, err := caClient.GetCAInfo()
	if err != nil {
		return nil, err
	}
	return caInfo, nil
}


func ReEnrollUser(params EnrollUserRequest) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	keystorePath, err := ioutil.TempDir("", "enroll")
	if err != nil {
		return nil, nil, nil, err
	}
	caClient, _, mgr, _, err := GetClient(FabricCAParams{
		TLSCert: params.TLSCert,
		URL:     params.URL,
		Name:    params.Name,
		MSPID:   params.MSPID,
	}, keystorePath)
	if err != nil {
		return nil, nil, nil, err
	}
	err = caClient.Reenroll(&api.ReenrollmentRequest{
		Name:     params.User,
		//Secret:   params.Secret,
		CAName:   params.Name,
		AttrReqs: params.Attributes,
		Profile:  params.Profile,
		Label:    "",
		CSR: &api.CSRInfo{
			Hosts: params.Hosts,
			CN:    params.CN,
		},
	})
	if err != nil {
		return nil, nil, nil, err
	}
	mgrIdentity := mgr[strings.ToLower(params.MSPID)].(*msp.IdentityManager)
	u, err := mgrIdentity.GetUser(params.User)
	if err != nil {
		return nil, nil, nil, err
	}
	hexSubjectID := hex.EncodeToString(u.PrivateKey().SKI())
	keyPath := fmt.Sprintf("%s/%s_sk", keystorePath, hexSubjectID)
	pkBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	userKey, err := utils.ParseECDSAPrivateKey(pkBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	userCrt, err := utils.ParseX509Certificate(u.EnrollmentCertificate())
	if err != nil {
		return nil, nil, nil, err
	}
	info, err := caClient.GetCAInfo()
	if err != nil {
		return nil, nil, nil, err
	}
	rootCrt, err := utils.ParseX509Certificate(info.CAChain)
	if err != nil {
		return nil, nil, nil, err
	}
	return userCrt, userKey, rootCrt, nil
}


func EnrollUser(params EnrollUserRequest) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	keystorePath, err := ioutil.TempDir("", "enroll")
	if err != nil {
		return nil, nil, nil, err
	}
	caClient, _, mgr, _, err := GetClient(FabricCAParams{
		TLSCert: params.TLSCert,
		URL:     params.URL,
		Name:    params.Name,
		MSPID:   params.MSPID,
	}, keystorePath)
	if err != nil {
		return nil, nil, nil, err
	}
	err = caClient.Enroll(&api.EnrollmentRequest{
		Name:     params.User,
		Secret:   params.Secret,
		CAName:   params.Name,
		AttrReqs: params.Attributes,
		Profile:  params.Profile,
		Label:    "",
		Type:     "x509",
		CSR: &api.CSRInfo{
			Hosts: params.Hosts,
			CN:    params.CN,
		},
	})
	if err != nil {
		return nil, nil, nil, err
	}
	mgrIdentity := mgr[strings.ToLower(params.MSPID)].(*msp.IdentityManager)
	u, err := mgrIdentity.GetUser(params.User)
	if err != nil {
		return nil, nil, nil, err
	}
	hexSubjectID := hex.EncodeToString(u.PrivateKey().SKI())
	keyPath := fmt.Sprintf("%s/%s_sk", keystorePath, hexSubjectID)
	pkBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	userKey, err := utils.ParseECDSAPrivateKey(pkBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	userCrt, err := utils.ParseX509Certificate(u.EnrollmentCertificate())
	if err != nil {
		return nil, nil, nil, err
	}
	info, err := caClient.GetCAInfo()
	if err != nil {
		return nil, nil, nil, err
	}
	rootCrt, err := utils.ParseX509Certificate(info.CAChain)
	if err != nil {
		return nil, nil, nil, err
	}
	return userCrt, userKey, rootCrt, nil
}

type GetUserRequest struct {
	TLSCert      string
	URL          string
	Name         string
	MSPID        string
	EnrollID     string
	EnrollSecret string
	User         string
}

func GetUser(params GetUserRequest) (*api.IdentityResponse, error) {
	keystorePath, err := ioutil.TempDir("", "enroll")
	if err != nil {
		return nil, err
	}

	caClient, _, _, _, err := GetClient(FabricCAParams{
		TLSCert:      params.TLSCert,
		URL:          params.URL,
		Name:         params.Name,
		MSPID:        params.MSPID,
		EnrollID:     params.EnrollID,
		EnrollSecret: params.EnrollSecret,
	}, keystorePath)
	if err != nil {
		return nil, err
	}
	kk, err := caClient.GetIdentity(params.User, params.Name)
	if err != nil {
		return nil, err
	}
	return kk, nil
}

type mockIsSecurityEnabled struct{}

func (m *mockIsSecurityEnabled) IsSecurityEnabled() bool {
	return true
}

type mockSecurityAlgorithm struct{}

func (m *mockSecurityAlgorithm) SecurityAlgorithm() string {
	return "SHA2"
}

type mockSecurityLevel struct{}

func (m *mockSecurityLevel) SecurityLevel() int {
	return 256
}

type mockSecurityProvider struct{}

func (m *mockSecurityProvider) SecurityProvider() string {
	return "sw"
}

type mockSoftVerify struct{}

func (m *mockSoftVerify) SoftVerify() bool {
	return true
}

type mockSecurityProviderLibPath struct{}

func (m *mockSecurityProviderLibPath) SecurityProviderLibPath() string {
	return ""
}

type mockSecurityProviderPin struct{}

func (m *mockSecurityProviderPin) SecurityProviderPin() string {
	return ""
}

type mockSecurityProviderLabel struct{}

func (m *mockSecurityProviderLabel) SecurityProviderLabel() string {
	return ""
}

type mockKeyStorePath struct {
	Path string
}

func (m *mockKeyStorePath) KeyStorePath() string {
	return m.Path
}

func GetClient(ca FabricCAParams, keyStorePath string) (*msp.CAClientImpl, *msp.MemoryUserStore, map[string]mspprov.IdentityManager, core.CryptoSuite, error) {
	m1 := &mockIsSecurityEnabled{}
	m2 := &mockSecurityAlgorithm{}
	m3 := &mockSecurityLevel{}
	m4 := &mockSecurityProvider{}
	m5 := &mockSoftVerify{}
	m6 := &mockSecurityProviderLibPath{}
	m7 := &mockSecurityProviderPin{}
	m8 := &mockSecurityProviderLabel{}
	m9 := &mockKeyStorePath{
		Path: keyStorePath,
	}
	mspID := ca.MSPID
	fabricConfig, err := getFabricConfig(ca)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	configYaml, err := yaml.Marshal(fabricConfig)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	configBackend, err := config.FromRaw(configYaml, "yaml")()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cryptSuiteConfig2 := cryptosuite.ConfigFromBackend(configBackend...)
	cryptSuiteConfigOption, err := cryptosuite.BuildCryptoSuiteConfigFromOptions(
		m1, m2, m3, m4, m5, m6, m7, m8, m9,
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cryptSuiteConfig1, ok := cryptSuiteConfigOption.(*cryptosuite.CryptoConfigOptions)
	if !ok {
		return nil, nil, nil, nil, errors.New(fmt.Sprintf("BuildCryptoSuiteConfigFromOptions did not return an Options instance %T", cryptSuiteConfigOption))
	}
	cryptSuiteConfig := cryptosuite.UpdateMissingOptsWithDefaultConfig(cryptSuiteConfig1, cryptSuiteConfig2)

	endpointConfig, err := fabImpl.ConfigFromBackend(configBackend...)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	identityConfig, err := msp.ConfigFromBackend(configBackend...)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cryptoSuite, err := sw.GetSuiteByConfig(cryptSuiteConfig)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	userStore := msp.NewMemoryUserStore()
	identityManagers := make(map[string]mspprov.IdentityManager)
	netConfig := endpointConfig.NetworkConfig()
	if netConfig == nil {
		panic("failed to get network config")
	}
	for orgName := range netConfig.Organizations {
		mgr, err1 := msp.NewIdentityManager(orgName, userStore, cryptoSuite, endpointConfig)
		if err1 != nil {
			panic(fmt.Sprintf("failed to initialize identity manager for organization: %s, cause :%s", orgName, err1))
		}
		identityManagers[orgName] = mgr
	}

	identityManagerProvider := &identityManagerProvider{identityManager: identityManagers}
	ctxProvider := fabricctx.NewProvider(
		fabricctx.WithIdentityManagerProvider(identityManagerProvider),
		fabricctx.WithUserStore(userStore),
		fabricctx.WithCryptoSuite(cryptoSuite),
		//fabricctx.WithCryptoSuiteConfig(cryptSuiteConfig),
		fabricctx.WithEndpointConfig(endpointConfig),
		fabricctx.WithIdentityConfig(identityConfig),
	)
	fctx := &fabricctx.Client{Providers: ctxProvider}
	client, err := msp.NewCAClient(mspID, fctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return client, userStore, identityManagers, cryptoSuite, nil
}

type identityManagerProvider struct {
	identityManager map[string]mspprov.IdentityManager
}

// IdentityManager returns the organization's identity manager
func (p *identityManagerProvider) IdentityManager(orgName string) (mspprov.IdentityManager, bool) {
	im, ok := p.identityManager[strings.ToLower(orgName)]
	if !ok {
		return nil, false
	}
	return im, true
}
