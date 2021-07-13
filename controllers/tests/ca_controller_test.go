package tests

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/kfsoftware/hlf-operator/controllers/ca"
	operatorv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/client/clientset/versioned"
	log "github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"strconv"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"

	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/api/hlf.kungfusoftware.es/v1alpha1"
	"github.com/kfsoftware/hlf-operator/controllers/certs"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"github.com/lithammer/shortuuid/v3"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	// +kubebuilder:scaffold:imports
)

func getOrderers(releaseName string, ns string) []hlfv1alpha1.FabricOrdererNode {
	hlfClient, err := operatorv1alpha1.NewForConfig(RestConfig)
	Expect(err).ToNot(HaveOccurred())
	ctx := context.Background()
	ordNodesRes, err := hlfClient.HlfV1alpha1().FabricOrdererNodes(ns).List(
		ctx,
		v1.ListOptions{
			LabelSelector: fmt.Sprintf("release=%s", releaseName),
		},
	)
	Expect(err).ToNot(HaveOccurred())
	return ordNodesRes.Items
}

const (
	defTimeoutSecs  = "240s"
	peerTimeoutSecs = "240s"
	defInterval     = "1s"
	systemChannelID = "system-channel"
)

func getClientForOrderer(updatedOrderer *hlfv1alpha1.FabricOrderingService, updatedCA *hlfv1alpha1.FabricCA) *resmgmt.Client {
	ip, err := utils.GetPublicIPKubernetes(ClientSet)
	Expect(err).ToNot(HaveOccurred())
	caurl := fmt.Sprintf("https://%s:%d", ip, updatedCA.Status.NodePort)
	caName := "ca"
	tlsCertString := updatedCA.Status.TlsCert
	caCert := updatedCA.Status.CACert
	enrollID := updatedCA.Spec.CA.Registry.Identities[0].Name
	enrollSecret := updatedCA.Spec.CA.Registry.Identities[0].Pass

	mspID := updatedOrderer.Spec.MspID
	userClient := "org1admin"
	userClientPW := "org1adminpw"
	registerParams := certs.RegisterUserRequest{
		TLSCert:      tlsCertString,
		URL:          caurl,
		Name:         caName,
		MSPID:        mspID,
		EnrollID:     enrollID,
		EnrollSecret: enrollSecret,
		User:         userClient,
		Secret:       userClientPW,
		Type:         "admin",
		Attributes:   nil,
	}
	_, err = certs.RegisterUser(registerParams)

	crt, pk, rootCrt, err := certs.EnrollUser(certs.EnrollUserRequest{
		TLSCert: tlsCertString,
		URL:     caurl,
		Name:    caName,
		MSPID:   mspID,
		User:    userClient,
		Secret:  userClientPW,
		Profile: "",
	})
	Expect(err).ToNot(HaveOccurred())
	Expect(crt).ToNot(BeNil())
	Expect(pk).ToNot(BeNil())
	Expect(rootCrt).ToNot(BeNil())

	certPem := string(utils.EncodeX509Certificate(crt))
	pkPem, err := utils.EncodePrivateKey(pk)
	Expect(err).ToNot(HaveOccurred())

	configYamlTpl := `
name: test-network-org1
version: 1.0.0
client:
  organization: OrdererMSP
  connection:
    timeout:
      peer:
        endorser: "300"
organizations:
  OrdererMSP:
    mspid: OrdererMSP
    cryptoPath: /tmp/cryptopath
    users:
      admin:
        key:
          pem: |
{{ .AdminKey | indent 12 }}

        cert:
          pem: |
{{ .AdminCert | indent 12 }}

    certificateAuthorities: []
    peers: []
    orderers:
    - "orderer"
certificateAuthorities: {}
peers: {}
orderers:
  "orderer":
    url: {{ .OrdUrl }}
    grpcOptions:
      allow-insecure: true
    tlsCACerts:
      pem: |
{{ .TlsCACrt | indent 8 }}

channels: {}
`
	tmpl, err := template.New("test").Funcs(sprig.HermeticTxtFuncMap()).Parse(configYamlTpl)
	var buf bytes.Buffer
	ordNodes := getOrderers(
		updatedOrderer.Name,
		updatedOrderer.Namespace,
	)
	ordNode := ordNodes[0]

	ordURL := fmt.Sprintf("grpcs://%s:%d", ip, ordNode.Status.NodePort)
	Expect(err).ToNot(HaveOccurred())
	err = tmpl.Execute(&buf, map[string]interface{}{
		"AdminKey":  string(pkPem),
		"AdminCert": certPem,
		"TlsCACrt":  caCert,
		"OrdUrl":    ordURL,
	})
	configYaml := buf.Bytes()
	log.Print(string(configYaml))
	configBackend := config.FromRaw(configYaml, "yaml")
	sdk, err := fabsdk.New(configBackend)
	Expect(err).ToNot(HaveOccurred())
	org1AdminClientContext := sdk.Context(
		fabsdk.WithUser("admin"),
		fabsdk.WithOrg("OrdererMSP"),
	)
	ordClient, err := resmgmt.New(org1AdminClientContext)
	Expect(err).ToNot(HaveOccurred())
	return ordClient
}
func randomFabricCA(releaseName string, namespace string) *hlfv1alpha1.FabricCA {
	fabricCARegistry := hlfv1alpha1.FabricCARegistry{
		MaxEnrollments: -1,
		Identities: []hlfv1alpha1.FabricCAIdentity{
			{
				Name:        "enroll",
				Pass:        "enrollpw",
				Type:        "client",
				Affiliation: "",
				Attrs: hlfv1alpha1.FabricCAIdentityAttrs{
					RegistrarRoles: "*",
					DelegateRoles:  "*",
					Attributes:     "*",
					Revoker:        true,
					IntermediateCA: true,
					GenCRL:         true,
					AffiliationMgr: true,
				},
			},
		},
	}
	subject := hlfv1alpha1.FabricCASubject{
		CN: "ca",
		C:  "ES",
		ST: "Alicante",
		O:  "Kung Fu Software",
		L:  "Alicante",
		OU: "Tech",
	}
	tlsSubject := hlfv1alpha1.FabricCASubject{
		CN: "tlsca",
		C:  "ES",
		ST: "Alicante",
		O:  "Kung Fu Software",
		L:  "Alicante",
		OU: "Tech",
	}
	cabccsp := hlfv1alpha1.FabricCABCCSP{
		Default: "SW",
		SW: hlfv1alpha1.FabricCABCCSPSW{
			Hash:     "SHA2",
			Security: "256",
		},
	}
	cfg := hlfv1alpha1.FabricCACFG{
		Identities:   hlfv1alpha1.FabricCACFGIdentities{AllowRemove: true},
		Affiliations: hlfv1alpha1.FabricCACFGAffilitions{AllowRemove: true},
	}
	resources, err := getDefaultResources()
	Expect(err).ToNot(HaveOccurred())

	fabricCa := &hlfv1alpha1.FabricCA{
		TypeMeta: NewTypeMeta("FabricCA"),
		ObjectMeta: v1.ObjectMeta{
			Name:      releaseName,
			Namespace: namespace,
		},
		Spec: hlfv1alpha1.FabricCASpec{

			Istio: &hlfv1alpha1.FabricIstio{
				Hosts: []string{},
			},
			Database: hlfv1alpha1.FabricCADatabase{
				Type:       "sqlite3",
				Datasource: "fabric-ca-server.db",
			},
			Hosts: []string{
				"localhost",
				releaseName,
				fmt.Sprintf("%s.%s", releaseName, namespace),
			},
			Service: hlfv1alpha1.FabricCASpecService{
				ServiceType: "NodePort",
			},
			CLRSizeLimit: 512000,
			Image:        "hyperledger/fabric-ca",
			Version:      "1.4.9",
			Debug:        true,
			TLS:          hlfv1alpha1.FabricCATLSConf{Subject: subject},
			CA: hlfv1alpha1.FabricCAItemConf{
				Name:    "ca",
				CFG:     cfg,
				Subject: subject,
				CSR: hlfv1alpha1.FabricCACSR{
					CN:    "ca",
					Hosts: []string{"localhost"},
					Names: []hlfv1alpha1.FabricCANames{
						{
							C:  "US",
							ST: "",
							O:  "Hyperledger",
							L:  "",
							OU: "North Carolina",
						},
					},
					CA: hlfv1alpha1.FabricCACSRCA{
						Expiry:     "131400h",
						PathLength: 0,
					},
				},
				CRL:          hlfv1alpha1.FabricCACRL{Expiry: "24h"},
				Registry:     fabricCARegistry,
				Intermediate: hlfv1alpha1.FabricCAIntermediate{},
				BCCSP:        cabccsp,
			},
			TLSCA: hlfv1alpha1.FabricCAItemConf{
				Name:    "tlsca",
				Subject: tlsSubject,
				CFG:     cfg,
				CSR: hlfv1alpha1.FabricCACSR{
					CN:    "tlsca",
					Hosts: []string{"localhost"},
					Names: []hlfv1alpha1.FabricCANames{
						{
							C:  "US",
							ST: "",
							O:  "Hyperledger",
							L:  "",
							OU: "North Carolina",
						},
					},
					CA: hlfv1alpha1.FabricCACSRCA{
						Expiry:     "131400h",
						PathLength: 0,
					},
				},
				CRL:          hlfv1alpha1.FabricCACRL{Expiry: "24h"},
				Registry:     fabricCARegistry,
				Intermediate: hlfv1alpha1.FabricCAIntermediate{},
				BCCSP:        cabccsp,
			},
			Cors: hlfv1alpha1.Cors{
				Enabled: false,
				Origins: []string{},
			},
			Resources: resources,
			Storage: hlfv1alpha1.Storage{
				Size:         "3Gi",
				StorageClass: "",
				AccessMode:   "ReadWriteOnce",
			},
			Metrics: hlfv1alpha1.FabricCAMetrics{
				Provider: "prometheus",
				Statsd: &hlfv1alpha1.FabricCAMetricsStatsd{
					Network:       "udp",
					Address:       "127.0.0.1:8125",
					WriteInterval: "10s",
					Prefix:        "server",
				},
			},
		},
	}
	Expect(K8sClient.Create(context.Background(), fabricCa)).Should(Succeed())
	updatedCA := &hlfv1alpha1.FabricCA{}
	caKey := types.NamespacedName{Namespace: namespace, Name: releaseName}
	Eventually(
		func() bool {
			err := K8sClient.Get(context.Background(), caKey, updatedCA)
			if err != nil {
				return false
			}
			ctrl.Log.WithName("test").Info("after update", "updatedCA", updatedCA)
			return updatedCA.Status.Status == hlfv1alpha1.RunningStatus
		},
		defTimeoutSecs,
		defInterval,
	).Should(BeTrue(), "ca status should have been updated")
	return updatedCA
}
func getSDKForPeer(peer *hlfv1alpha1.FabricPeer, ca *hlfv1alpha1.FabricCA) *fabsdk.FabricSDK {
	userClient := "orgadmin"
	userClientPW := "orgadminpw"
	caName := "ca"
	enrollID := ca.Spec.CA.Registry.Identities[0].Name
	ip, err := utils.GetPublicIPKubernetes(ClientSet)
	Expect(err).ToNot(HaveOccurred())
	caURL := fmt.Sprintf("https://%s:%d", ip, ca.Status.NodePort)

	enrollSecret := ca.Spec.CA.Registry.Identities[0].Pass
	caCert := ca.Status.CACert
	tlsCertString := ca.Status.TlsCert
	mspID := peer.Spec.MspID
	registerParams := certs.RegisterUserRequest{
		TLSCert:      tlsCertString,
		URL:          caURL,
		Name:         caName,
		MSPID:        mspID,
		EnrollID:     enrollID,
		EnrollSecret: enrollSecret,
		User:         userClient,
		Secret:       userClientPW,
		Type:         "admin",
		Attributes:   nil,
	}
	_, err = certs.RegisterUser(registerParams)

	crt, pk, rootCrt, err := certs.EnrollUser(certs.EnrollUserRequest{
		TLSCert: tlsCertString,
		URL:     caURL,
		Name:    caName,
		MSPID:   mspID,
		User:    userClient,
		Secret:  userClientPW,
		Profile: "",
	})
	Expect(err).ToNot(HaveOccurred())
	Expect(crt).ToNot(BeNil())
	Expect(pk).ToNot(BeNil())
	Expect(rootCrt).ToNot(BeNil())
	certPem := string(utils.EncodeX509Certificate(crt))
	pkPem, err := utils.EncodePrivateKey(pk)
	Expect(err).ToNot(HaveOccurred())
	configYamlTpl := `
name: test-network-org1
version: 1.0.0
client:
  organization: {{.MSPID}}
  connection:
    timeout:
      peer:
        endorser: "300"
organizations:
  {{.MSPID}}:
    mspid: {{.MSPID}}
    cryptoPath: /tmp/cryptopath
    users:
      admin:
        key:
          pem: |
{{ .AdminKey | indent 12 }}
        cert:
          pem: |
{{ .AdminCert | indent 12 }}

    certificateAuthorities: []
    peers:
    - "peer"
certificateAuthorities: {}
peers:
  "peer":
    url: {{ .PeerUrl }}
    grpcOptions:
      hostnameOverride: ""
      ssl-target-name-override: ""
      allow-insecure: true
    tlsCACerts:
      pem: |
{{ .TlsCACrt | indent 8 }}

channels:
  _default:
    peers:
      "peer":
        endorsingPeer: true
        chaincodeQuery: true
        ledgerQuery: true
        eventSource: true


`
	tmpl, err := template.New("test").Funcs(sprig.HermeticTxtFuncMap()).Parse(configYamlTpl)
	Expect(err).ToNot(HaveOccurred())
	var buf bytes.Buffer
	peerURL := fmt.Sprintf("grpcs://%s:%d", ip, peer.Status.NodePort)
	err = tmpl.Execute(&buf, map[string]interface{}{
		"MSPID":     peer.Spec.MspID,
		"AdminKey":  string(pkPem),
		"AdminCert": certPem,
		"TlsCACrt":  caCert,
		"PeerUrl":   peerURL,
	})
	configYaml := buf.Bytes()
	configBackend := config.FromRaw(configYaml, "yaml")
	sdk, err := fabsdk.New(
		configBackend,
	)
	Expect(err).ToNot(HaveOccurred())
	return sdk
}
func getSDKForPeerWithOrderer(peer *hlfv1alpha1.FabricPeer, ca *hlfv1alpha1.FabricCA, orderer *hlfv1alpha1.FabricOrderingService, ordererCA *hlfv1alpha1.FabricCA) *fabsdk.FabricSDK {
	userClient := "orgadmin"
	userClientPW := "orgadminpw"
	caName := "ca"
	enrollID := ca.Spec.CA.Registry.Identities[0].Name
	ip, err := utils.GetPublicIPKubernetes(ClientSet)
	Expect(err).ToNot(HaveOccurred())
	caURL := fmt.Sprintf("grpcs://%s:%d", ip, peer.Status.NodePort)
	enrollSecret := ca.Spec.CA.Registry.Identities[0].Pass
	caCert := ca.Status.CACert
	tlsCertString := ca.Status.TlsCert
	mspID := peer.Spec.MspID
	registerParams := certs.RegisterUserRequest{
		TLSCert:      tlsCertString,
		URL:          caURL,
		Name:         caName,
		MSPID:        mspID,
		EnrollID:     enrollID,
		EnrollSecret: enrollSecret,
		User:         userClient,
		Secret:       userClientPW,
		Type:         "admin",
		Attributes:   nil,
	}
	_, err = certs.RegisterUser(registerParams)

	crt, pk, rootCrt, err := certs.EnrollUser(certs.EnrollUserRequest{
		TLSCert: tlsCertString,
		URL:     caURL,
		Name:    caName,
		MSPID:   mspID,
		User:    userClient,
		Secret:  userClientPW,
		Profile: "",
	})
	Expect(err).ToNot(HaveOccurred())
	Expect(crt).ToNot(BeNil())
	Expect(pk).ToNot(BeNil())
	Expect(rootCrt).ToNot(BeNil())
	certPem := string(utils.EncodeX509Certificate(crt))
	pkPem, err := utils.EncodePrivateKey(pk)
	Expect(err).ToNot(HaveOccurred())
	configYamlTpl := `
name: test-network-org1
version: 1.0.0
client:
  organization: {{.MSPID}}
  connection:
    timeout:
      peer:
        endorser: "300"
organizations:
  {{.MSPID}}:
    mspid: {{.MSPID}}
    cryptoPath: /tmp/cryptopath
    users:
      admin:
        key:
          pem: |
{{ .AdminKey | indent 12 }}
        cert:
          pem: |
{{ .AdminCert | indent 12 }}
    certificateAuthorities: []
    peers:
    - "peer"
certificateAuthorities: {}
peers:
  "peer":
    url: {{ .PeerUrl }}
    grpcOptions:
      allow-insecure: true
    tlsCACerts:
      pem: |
{{ .TlsCACrt | indent 8 }}
orderers:
  "orderer":
    url: {{ .OrdUrl }}
    grpcOptions:
      allow-insecure: true
    tlsCACerts:
      pem: |
{{ .OrdTlsCACrt | indent 8 }}

channels:
  _default:
    peers:
      "peer":
        endorsingPeer: true
        chaincodeQuery: true
        ledgerQuery: true
        eventSource: true
    orderers: ["orderer"]

`
	tmpl, err := template.New("test").Funcs(sprig.HermeticTxtFuncMap()).Parse(configYamlTpl)
	var buf bytes.Buffer
	peerURL := fmt.Sprintf("grpcs://%s:%d", ip, peer.Status.NodePort)
	Expect(err).ToNot(HaveOccurred())
	ordNodes := getOrderers(
		orderer.Name,
		orderer.Namespace,
	)
	ordNode := ordNodes[0]
	ordNodeURL := fmt.Sprintf("grpcs://%s:%d", ip, ordNode.Status.NodePort)
	err = tmpl.Execute(&buf, map[string]interface{}{
		"MSPID":       peer.Spec.MspID,
		"AdminKey":    string(pkPem),
		"AdminCert":   certPem,
		"TlsCACrt":    caCert,
		"PeerUrl":     peerURL,
		"OrdTlsCACrt": ordererCA.Status.CACert,
		"OrdUrl":      ordNodeURL,
	})
	configYaml := buf.Bytes()
	configBackend := config.FromRaw(configYaml, "yaml")
	sdk, err := fabsdk.New(
		configBackend,
	)
	Expect(err).ToNot(HaveOccurred())
	return sdk
}
func getClientForPeer(peer *hlfv1alpha1.FabricPeer, ca *hlfv1alpha1.FabricCA) *resmgmt.Client {
	sdk := getSDKForPeer(peer, ca)
	org1AdminClientContext := sdk.Context(
		fabsdk.WithUser("admin"),
		fabsdk.WithOrg(peer.Spec.MspID),
	)
	resClient, err := resmgmt.New(org1AdminClientContext)
	Expect(err).ToNot(HaveOccurred())
	return resClient
}
func getClientForPeerWithOrderer(peer *hlfv1alpha1.FabricPeer, ca *hlfv1alpha1.FabricCA, orderer *hlfv1alpha1.FabricOrderingService, ordererCA *hlfv1alpha1.FabricCA) *resmgmt.Client {
	sdk := getSDKForPeerWithOrderer(peer, ca, orderer, ordererCA)
	org1AdminClientContext := sdk.Context(
		fabsdk.WithUser("admin"),
		fabsdk.WithOrg(peer.Spec.MspID),
	)
	resClient, err := resmgmt.New(org1AdminClientContext)
	Expect(err).ToNot(HaveOccurred())
	return resClient
}

type createOrdererParams struct {
	MSPID string
}

func createOrdererNode(releaseName string, namespace string, params createOrdererParams, certauth *hlfv1alpha1.FabricCA) *hlfv1alpha1.FabricOrdererNode {
	publicIP, err := utils.GetPublicIPKubernetes(ClientSet)
	Expect(err).ToNot(HaveOccurred())
	mspID := params.MSPID
	By("create a fabric orderer")
	caHost := publicIP
	caPort := certauth.Status.NodePort
	caName := "ca"
	caTLSCert := certauth.Status.TlsCert
	enrollID := certauth.Spec.CA.Registry.Identities[0].Name
	enrollSecret := certauth.Spec.CA.Registry.Identities[0].Pass
	caURL := fmt.Sprintf("https://%s:%d", caHost, caPort)
	ordEnrollID := "orderer"
	ordEnrollSecret := "ordererpw"
	ordType := "orderer"
	log.Infof("Registering user with credentials %s:%s and user %s:%s", enrollID, enrollSecret, ordEnrollID, ordEnrollSecret)
	_, err = certs.RegisterUser(certs.RegisterUserRequest{
		TLSCert:      caTLSCert,
		URL:          caURL,
		Name:         caName,
		MSPID:        mspID,
		EnrollID:     enrollID,
		EnrollSecret: enrollSecret,
		User:         ordEnrollID,
		Secret:       ordEnrollSecret,
		Type:         ordType,
		Attributes:   nil,
	})
	if err != nil {
		log.Errorf("Failed to register user %s %v", ordEnrollID, err)
	}
	resources, err := getDefaultResources()
	Expect(err).ToNot(HaveOccurred())
	fabricOrderer := &hlfv1alpha1.FabricOrdererNode{
		TypeMeta: NewTypeMeta("FabricOrdererNode"),
		ObjectMeta: v1.ObjectMeta{
			Name:      releaseName,
			Namespace: namespace,
		},
		Spec: hlfv1alpha1.FabricOrdererNodeSpec{
			Storage: hlfv1alpha1.Storage{
				Size:         "30Gi",
				StorageClass: "standard",
				AccessMode:   "ReadWriteOnce",
			},
			BootstrapMethod:             "none",
			ChannelParticipationEnabled: true,
			PullPolicy:                  corev1.PullAlways,
			Image:                       "hyperledger/fabric-orderer",
			Tag:                         "amd64-2.3.0",
			MspID:                       mspID,
			Replicas:                    1,
			Resources:                   resources,
			Secret: &hlfv1alpha1.Secret{
				Enrollment: hlfv1alpha1.Enrollment{
					Component: hlfv1alpha1.Component{
						Cahost: caHost,
						Caname: caName,
						Caport: caPort,
						Catls: hlfv1alpha1.Catls{
							Cacert: base64.StdEncoding.EncodeToString([]byte(caTLSCert)),
						},
						Enrollid:     enrollID,
						Enrollsecret: enrollSecret,
					},
					TLS: hlfv1alpha1.TLS{
						Cahost: caHost,
						Caname: caName,
						Caport: caPort,
						Catls: hlfv1alpha1.Catls{
							Cacert: base64.StdEncoding.EncodeToString([]byte(caTLSCert)),
						},
						Enrollid:     enrollID,
						Enrollsecret: enrollSecret,
						Csr: hlfv1alpha1.Csr{
							Hosts: []string{},
							CN:    "",
						},
					},
				},
			},
			Service: hlfv1alpha1.OrdererNodeService{
				Type: "NodePort",
			},
		},
	}
	Expect(K8sClient.Create(context.Background(), fabricOrderer)).Should(Succeed())
	return fabricOrderer
}

func verifyCADeployment(fabricCA *hlfv1alpha1.FabricCA) {
	publicIP, err := utils.GetPublicIPKubernetes(ClientSet)
	Expect(err).ToNot(HaveOccurred())
	caurl := fmt.Sprintf("https://%s:%d", publicIP, fabricCA.Status.NodePort)
	caName := "ca"
	tlsCertString := fabricCA.Status.TlsCert
	enrollID := fabricCA.Spec.CA.Registry.Identities[0].Name
	enrollSecret := fabricCA.Spec.CA.Registry.Identities[0].Pass
	By("enroll the admin user")
	mspID := "Org1MSP"
	tlsCert, tlsKey, tlsRootCert, err := certs.EnrollUser(certs.EnrollUserRequest{
		TLSCert: tlsCertString,
		URL:     caurl,
		Name:    caName,
		MSPID:   mspID,
		User:    enrollID,
		Secret:  enrollSecret,
	})
	Expect(err).ToNot(HaveOccurred())
	Expect(tlsCert).ToNot(BeNil())
	Expect(tlsKey).ToNot(BeNil())
	Expect(tlsRootCert).ToNot(BeNil())

	registerParams := certs.RegisterUserRequest{
		TLSCert:      tlsCertString,
		URL:          caurl,
		Name:         caName,
		MSPID:        mspID,
		EnrollID:     enrollID,
		EnrollSecret: enrollSecret,
		User:         "peer",
		Secret:       "peerpw",
		Type:         "peer",
		Attributes:   nil,
	}
	secret, err := certs.RegisterUser(registerParams)
	Expect(err).ToNot(HaveOccurred())
	Expect(secret).To(Equal(registerParams.Secret))
}

var _ = Describe("Fabric Controllers", func() {
	FabricNamespace := ""
	BeforeEach(func() {
		FabricNamespace = "hlf-operator-" + getRandomChannelID()
		testNamespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: FabricNamespace,
			},
		}
		log.Infof("Creating namespace %s", FabricNamespace)
		Expect(K8sClient.Create(context.Background(), testNamespace)).Should(Succeed())
	})
	AfterEach(func() {
		log.Infof("Deleting namespace %s", FabricNamespace)
		//Expect(ClientSet.CoreV1().Namespaces().Delete(context.Background(), FabricNamespace, v1.DeleteOptions{})).Should(Succeed())
	})
	Specify("create a new Fabric CA instance", func() {
		By("create the CA object")
		objName := "org1-ca"
		fabricCARegistry := hlfv1alpha1.FabricCARegistry{
			MaxEnrollments: -1,
			Identities: []hlfv1alpha1.FabricCAIdentity{
				{
					Name:        "enroll",
					Pass:        "enrollpw",
					Type:        "client",
					Affiliation: "",
					Attrs: hlfv1alpha1.FabricCAIdentityAttrs{
						RegistrarRoles: "*",
						DelegateRoles:  "*",
						Attributes:     "*",
						Revoker:        true,
						IntermediateCA: true,
						GenCRL:         true,
						AffiliationMgr: true,
					},
				},
			},
		}
		subject := hlfv1alpha1.FabricCASubject{
			CN: "ca",
			C:  "ES",
			ST: "Alicante",
			O:  "Kung Fu Software",
			L:  "Alicante",
			OU: "Tech",
		}
		tlsSubject := hlfv1alpha1.FabricCASubject{
			CN: "tlsca",
			C:  "ES",
			ST: "Alicante",
			O:  "Kung Fu Software",
			L:  "Alicante",
			OU: "Tech",
		}
		cabccsp := hlfv1alpha1.FabricCABCCSP{
			Default: "SW",
			SW: hlfv1alpha1.FabricCABCCSPSW{
				Hash:     "SHA2",
				Security: "256",
			},
		}
		cfg := hlfv1alpha1.FabricCACFG{
			Identities:   hlfv1alpha1.FabricCACFGIdentities{AllowRemove: true},
			Affiliations: hlfv1alpha1.FabricCACFGAffilitions{AllowRemove: true},
		}
		resources, err := getDefaultResources()
		Expect(err).ToNot(HaveOccurred())
		fabricCa := &hlfv1alpha1.FabricCA{
			TypeMeta: NewTypeMeta("FabricCA"),
			ObjectMeta: v1.ObjectMeta{
				Name:      objName,
				Namespace: FabricNamespace,
			},
			Spec: hlfv1alpha1.FabricCASpec{
				Istio: &hlfv1alpha1.FabricIstio{
					Hosts: []string{},
				},
				Database: hlfv1alpha1.FabricCADatabase{
					Type:       "sqlite3",
					Datasource: "fabric-ca-server.db",
				},
				Hosts: []string{
					"localhost",
					objName,
					fmt.Sprintf("%s.%s", objName, FabricNamespace),
				},
				Service: hlfv1alpha1.FabricCASpecService{
					ServiceType: "NodePort",
				},
				CLRSizeLimit: 512000,
				Image:        "hyperledger/fabric-ca",
				Version:      "1.4.9",
				Debug:        true,
				TLS:          hlfv1alpha1.FabricCATLSConf{Subject: subject},
				CA: hlfv1alpha1.FabricCAItemConf{
					Name:    "ca",
					Subject: subject,
					CFG:     cfg,
					CSR: hlfv1alpha1.FabricCACSR{
						CN:    "ca",
						Hosts: []string{"localhost"},
						Names: []hlfv1alpha1.FabricCANames{
							{
								C:  "US",
								ST: "",
								O:  "Hyperledger",
								L:  "",
								OU: "North Carolina",
							},
						},
						CA: hlfv1alpha1.FabricCACSRCA{
							Expiry:     "131400h",
							PathLength: 0,
						},
					},
					CRL:          hlfv1alpha1.FabricCACRL{Expiry: "24h"},
					Registry:     fabricCARegistry,
					Intermediate: hlfv1alpha1.FabricCAIntermediate{},
					BCCSP:        cabccsp,
				},
				TLSCA: hlfv1alpha1.FabricCAItemConf{
					Name:    "tlsca",
					Subject: tlsSubject,
					CFG:     cfg,
					CSR: hlfv1alpha1.FabricCACSR{
						CN:    "tlsca",
						Hosts: []string{"localhost"},
						Names: []hlfv1alpha1.FabricCANames{
							{
								C:  "US",
								ST: "",
								O:  "Hyperledger",
								L:  "",
								OU: "North Carolina",
							},
						},
						CA: hlfv1alpha1.FabricCACSRCA{
							Expiry:     "131400h",
							PathLength: 0,
						},
					},
					CRL:          hlfv1alpha1.FabricCACRL{Expiry: "24h"},
					Registry:     fabricCARegistry,
					Intermediate: hlfv1alpha1.FabricCAIntermediate{},
					BCCSP:        cabccsp,
				},
				Cors: hlfv1alpha1.Cors{
					Enabled: false,
					Origins: []string{},
				},
				Resources: resources,
				Storage: hlfv1alpha1.Storage{
					Size:         "3Gi",
					StorageClass: "",
					AccessMode:   "ReadWriteOnce",
				},
				Metrics: hlfv1alpha1.FabricCAMetrics{
					Provider: "prometheus",
					Statsd: &hlfv1alpha1.FabricCAMetricsStatsd{
						Network:       "udp",
						Address:       "127.0.0.1:8125",
						WriteInterval: "10s",
						Prefix:        "server",
					},
				},
			},
		}
		log.Infof("Creating the fabric ca %s", fabricCa.Name)
		Expect(K8sClient.Create(context.Background(), fabricCa)).Should(Succeed())
		updatedCA := &hlfv1alpha1.FabricCA{}
		caKey := types.NamespacedName{Namespace: FabricNamespace, Name: objName}
		Eventually(
			func() bool {
				err := K8sClient.Get(context.Background(), caKey, updatedCA)
				if err != nil {
					return false
				}
				ctrl.Log.WithName("test").Info("status of ca %s", "status", updatedCA.Status)
				return updatedCA.Status.Status == hlfv1alpha1.RunningStatus
			},
			defTimeoutSecs,
			defInterval,
		).Should(BeTrue(), "ca status should have been updated")
		verifyCADeployment(updatedCA)
		Expect(K8sClient.Delete(context.Background(), updatedCA)).Should(Succeed())
		Eventually(
			func() bool {
				depName := ca.GetDeploymentName(objName)
				_, err := ClientSet.AppsV1().Deployments(FabricNamespace).Get(context.Background(), depName, v1.GetOptions{})
				if err != nil {
					return apierrors.IsNotFound(err)
				} else {
					return false
				}
			},
			defTimeoutSecs,
			defInterval,
		).Should(BeTrue(), "ca deployment should have been deleted")

	})
	Specify("create a new Fabric Orderer with channel participation", func() {
		releaseNameOrdCA := "org1-ca"
		releaseNameOrd := "org1-orderer"
		By("create a fabric ca")
		ordererCA := randomFabricCA(releaseNameOrdCA, FabricNamespace)
		Expect(ordererCA).ToNot(BeNil())
		By("create a fabric orderer")
		ordererMSPID := "OrdererMSP"
		ordParams := createOrdererParams{
			MSPID: ordererMSPID,
		}
		createOrdererNode(
			releaseNameOrd,
			FabricNamespace,
			ordParams,
			ordererCA,
		)
		orderer := &hlfv1alpha1.FabricOrdererNode{}
		ordererKey := types.NamespacedName{
			Namespace: FabricNamespace,
			Name:      releaseNameOrd,
		}
		Eventually(
			func() bool {
				err := K8sClient.Get(context.Background(), ordererKey, orderer)
				if err != nil {
					return false
				}
				ctrl.Log.WithName("test").Info("after update", "orderer", orderer)
				return orderer.Status.Status == hlfv1alpha1.RunningStatus
			},
			peerTimeoutSecs,
			defInterval,
		).Should(BeTrue(), "peer status should have been updated")
	})
})

func NewTypeMeta(kind string) metav1.TypeMeta {
	return metav1.TypeMeta{
		Kind:       kind,
		APIVersion: "hlf.kungfusoftware.es/v1alpha1",
	}
}

func getRandomChannelID() string {
	alphabet := "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	channelID := shortuuid.NewWithAlphabet(alphabet)

	for i := 1; i <= 9; i++ {
		channelID = strings.Replace(channelID, strconv.Itoa(i), "a", -1)
	}
	return strings.ToLower(channelID)
}
