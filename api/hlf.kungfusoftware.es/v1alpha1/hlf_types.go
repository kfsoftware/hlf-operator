/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"fmt"

	"github.com/operator-framework/operator-lib/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type CA struct {
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`
	// +kubebuilder:validation:MinLength=1
	Cert string `json:"cert"`
	// +kubebuilder:validation:MinLength=1
	User string `json:"user"`
	// +kubebuilder:validation:MinLength=1
	Password string `json:"password"`
}

// +kubebuilder:validation:Enum=couchdb;leveldb
type StateDB string

// Use LevelDB database
const StateDBLevelDB StateDB = "leveldb"

// Use CouchDB database
const StateDBCouchDB StateDB = "couchdb"

// +kubebuilder:validation:Enum="2.1.1";"2.2.0"
type FabricVersion string

type ExternalBuilder struct {
	Name string `json:"name"`
	Path string `json:"path"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	PropagateEnvironment []string `json:"propagateEnvironment"`
}

const DefaultImagePullPolicy = corev1.PullAlways

type ServiceMonitor struct {
	// +kubebuilder:default:=false
	Enabled bool `json:"enabled"`
	// +optional
	Labels map[string]string `json:"labels"`
	// +kubebuilder:default:=0
	SampleLimit int `json:"sampleLimit"`
	// +kubebuilder:default:="10s"
	Interval string `json:"interval"`
	// +kubebuilder:default:="10s"
	ScrapeTimeout string `json:"scrapeTimeout"`
}

// FabricPeerSpec defines the desired state of FabricPeer
type FabricPeerSpec struct {
	// +optional
	// +nullable
	UpdateCertificateTime *metav1.Time `json:"updateCertificateTime"`

	// +optional
	// +nullable
	ServiceMonitor *ServiceMonitor `json:"serviceMonitor"`
	// +optional
	// +nullable
	HostAliases []corev1.HostAlias `json:"hostAliases"`

	// +kubebuilder:default:=1
	Replicas int `json:"replicas"`
	// +kubebuilder:default:=""
	DockerSocketPath string `json:"dockerSocketPath"`
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	ExternalBuilders []ExternalBuilder `json:"externalBuilders"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Istio            *FabricIstio         `json:"istio"`
	Gossip           FabricPeerSpecGossip `json:"gossip"`
	ExternalEndpoint string               `json:"externalEndpoint"`
	// +kubebuilder:validation:MinLength=1
	Tag                      string            `json:"tag"`
	ImagePullPolicy          corev1.PullPolicy `json:"imagePullPolicy,omitempty"`
	ExternalChaincodeBuilder bool              `json:"external_chaincode_builder"`
	CouchDB                  FabricPeerCouchDB `json:"couchdb"`
	// +kubebuilder:validation:MinLength=3
	MspID     string              `json:"mspID"`
	Secret    Secret              `json:"secret"`
	Service   PeerService         `json:"service"`
	StateDb   StateDB             `json:"stateDb"`
	Storage   FabricPeerStorage   `json:"storage"`
	Discovery FabricPeerDiscovery `json:"discovery"`
	Logging   FabricPeerLogging   `json:"logging"`
	Resources FabricPeerResources `json:"resources"`
	Hosts     []string            `json:"hosts"`
}
type FabricPeerResources struct {
	Peer      corev1.ResourceRequirements `json:"peer"`
	CouchDB   corev1.ResourceRequirements `json:"couchdb"`
	Chaincode corev1.ResourceRequirements `json:"chaincode"`
}
type FabricPeerDiscovery struct {
	Period      string `json:"period"`
	TouchPeriod string `json:"touchPeriod"`
}
type FabricPeerLogging struct {
	Level    string `json:"level"`
	Peer     string `json:"peer"`
	Cauthdsl string `json:"cauthdsl"`
	Gossip   string `json:"gossip"`
	Grpc     string `json:"grpc"`
	Ledger   string `json:"ledger"`
	Msp      string `json:"msp"`
	Policies string `json:"policies"`
}
type FabricPeerStorage struct {
	CouchDB   Storage `json:"couchdb"`
	Peer      Storage `json:"peer"`
	Chaincode Storage `json:"chaincode"`
}
type FabricPeerCouchDB struct {
	User     string `json:"user"`
	Password string `json:"password"`
}
type FabricIstio struct {
	// +optional
	// +nullable
	Port int `json:"port"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Hosts []string `json:"hosts,omitempty"`
	// +kubebuilder:validation:Default=ingressgateway
	IngressGateway string `json:"ingressGateway"`
}

type FabricPeerSpecGossip struct {
	ExternalEndpoint  string `json:"externalEndpoint"`
	Bootstrap         string `json:"bootstrap"`
	Endpoint          string `json:"endpoint"`
	UseLeaderElection bool   `json:"useLeaderElection"`
	OrgLeader         bool   `json:"orgLeader"`
}
type Catls struct {
	Cacert string `json:"cacert"`
}
type Component struct {
	// +kubebuilder:validation:MinLength=1
	Cahost string `json:"cahost"`
	// +kubebuilder:validation:MinLength=1
	Caname string `json:"caname"`
	Caport int    `json:"caport"`
	Catls  Catls  `json:"catls"`
	// +kubebuilder:validation:MinLength=1
	Enrollid string `json:"enrollid"`
	// +kubebuilder:validation:MinLength=1
	Enrollsecret string `json:"enrollsecret"`
}

func (c *Component) CAUrl() string {
	return fmt.Sprintf("https://%s:%d", c.Cahost, c.Caport)
}

type Csr struct {
	// +optional
	Hosts []string `json:"hosts"`
	// +optional
	CN string `json:"cn"`
}
type TLS struct {
	Cahost string `json:"cahost"`
	Caname string `json:"caname"`
	Caport int    `json:"caport"`
	Catls  Catls  `json:"catls"`
	// +optional
	Csr          Csr    `json:"csr"`
	Enrollid     string `json:"enrollid"`
	Enrollsecret string `json:"enrollsecret"`
}
type Enrollment struct {
	Component Component `json:"component"`
	TLS       TLS       `json:"tls"`
}
type OrdererEnrollment struct {
	Component Component `json:"component"`
	TLS       TLS       `json:"tls"`
}
type Secret struct {
	Enrollment Enrollment `json:"enrollment"`
}
type OrdererNode struct {
	// +kubebuilder:validation:MinLength=1
	ID string `json:"id"`
	// +optional
	Host string `json:"host"`
	// +optional
	Port       int                   `json:"port"`
	Enrollment OrdererNodeEnrollment `json:"enrollment"`
}
type OrdererNodeEnrollment struct {
	TLS OrdererNodeEnrollmentTLS `json:"tls"`
}
type OrdererNodeEnrollmentTLS struct {
	// +optional
	Csr Csr `json:"csr"`
}

// +kubebuilder:validation:Enum=NodePort;ClusterIP;LoadBalancer
// +kubebuilder:default:NodePort
type ServiceType string

const ServiceTypeNodePort = "NodePort"
const ServiceTypeClusterIP = "ClusterIP"
const ServiceTypeLoadBalancer = "LoadBalancer"

type Service struct {
	Type ServiceType `json:"type"`
}

type PeerService struct {
	// +kubebuilder:validation:Enum=NodePort;ClusterIP;LoadBalancer
	// +kubebuilder:default:NodePort
	Type corev1.ServiceType `json:"type"`
}

// FabricPeerStatus defines the observed state of FabricPeer
type FabricPeerStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	Status     DeploymentStatus  `json:"status"`

	// +optional
	// +nullable
	LastCertificateUpdate *metav1.Time `json:"lastCertificateUpdate"`

	// +optional
	SignCert string `json:"signCert"`
	// +optional
	TlsCert string `json:"tlsCert"`
	// +optional
	TlsCACert string `json:"tlsCaCert"`
	// +optional
	SignCACert string `json:"signCaCert"`
	// +optional
	NodePort int `json:"port"`
}
type OrdererService struct {
	// +kubebuilder:validation:Enum=NodePort;ClusterIP;LoadBalancer
	// +kubebuilder:default:NodePort
	Type ServiceType `json:"type"`
}

type OrdererNodeService struct {
	Type               corev1.ServiceType `json:"type"`
	NodePortOperations int                `json:"nodePortOperations,omitempty"`
	NodePortRequest    int                `json:"nodePortRequest,omitempty"`
}

// FabricOrderingServiceSpec defines the desired state of FabricOrderingService
type FabricOrderingServiceSpec struct {
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`
	// +kubebuilder:validation:MinLength=1
	Tag string `json:"tag"`
	// +kubebuilder:validation:MinLength=3
	MspID         string               `json:"mspID"`
	Enrollment    OrdererEnrollment    `json:"enrollment"`
	Nodes         []OrdererNode        `json:"nodes"`
	Service       OrdererService       `json:"service"`
	Storage       Storage              `json:"storage"`
	SystemChannel OrdererSystemChannel `json:"systemChannel"`
}
type BootstrapMethod string

const (
	BootstrapMethodNone = "none"
	BootstrapMethodFile = "file"
)

// FabricOrdererNodeSpec defines the desired state of FabricOrdererNode
type FabricOrdererNodeSpec struct {
	// +optional
	// +nullable
	UpdateCertificateTime *metav1.Time `json:"updateCertificateTime"`
	// +optional
	// +nullable
	ServiceMonitor *ServiceMonitor `json:"serviceMonitor"`
	// +optional
	// +nullable
	HostAliases []corev1.HostAlias `json:"hostAliases"`

	Resources corev1.ResourceRequirements `json:"resources"`

	// +kubebuilder:default:=1
	Replicas int `json:"replicas"`
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`
	// +kubebuilder:validation:MinLength=1
	Tag string `json:"tag"`
	// +kubebuilder:default:="IfNotPresent"
	PullPolicy corev1.PullPolicy `json:"pullPolicy,omitempty"`
	// +kubebuilder:validation:MinLength=3
	MspID string `json:"mspID"`

	Genesis                     string             `json:"genesis"`
	BootstrapMethod             BootstrapMethod    `json:"bootstrapMethod"`
	ChannelParticipationEnabled bool               `json:"channelParticipationEnabled"`
	Storage                     Storage            `json:"storage"`
	Service                     OrdererNodeService `json:"service"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Secret *Secret `json:"secret"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Istio *FabricIstio `json:"istio"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	AdminIstio *FabricIstio `json:"adminIstio"`
}

type OrdererSystemChannel struct {
	// +kubebuilder:validation:MinLength=3
	Name   string        `json:"name"`
	Config ChannelConfig `json:"config"`
}
type OrdererCapabilities struct {
	V2_0 bool `json:"V2_0"`
}
type ApplicationCapabilities struct {
	V2_0 bool `json:"V2_0"`
}
type ChannelCapabilities struct {
	V2_0 bool `json:"V2_0"`
}
type ChannelConfig struct {
	BatchTimeout            string                  `json:"batchTimeout"`
	MaxMessageCount         int                     `json:"maxMessageCount"`
	AbsoluteMaxBytes        int                     `json:"absoluteMaxBytes"`
	PreferredMaxBytes       int                     `json:"preferredMaxBytes"`
	OrdererCapabilities     OrdererCapabilities     `json:"ordererCapabilities"`
	ApplicationCapabilities ApplicationCapabilities `json:"applicationCapabilities"`
	ChannelCapabilities     ChannelCapabilities     `json:"channelCapabilities"`
	SnapshotIntervalSize    int                     `json:"snapshotIntervalSize"`
	TickInterval            string                  `json:"tickInterval"`
	ElectionTick            int                     `json:"electionTick"`
	HeartbeatTick           int                     `json:"heartbeatTick"`
	MaxInflightBlocks       int                     `json:"maxInflightBlocks"`
}

// FabricOrderingServiceStatus defines the observed state of FabricOrderingService
type FabricOrderingServiceStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Status     DeploymentStatus  `json:"status"`
}

// FabricOrdererNodeStatus defines the observed state of FabricOrdererNode
type FabricOrdererNodeStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Status     DeploymentStatus  `json:"status"`

	// +optional
	// +nullable
	LastCertificateUpdate *metav1.Time `json:"lastCertificateUpdate"`

	// +optional
	SignCert string `json:"signCert"`
	// +optional
	TlsCert string `json:"tlsCert"`
	// +optional
	TlsAdminCert string `json:"tlsAdminCert"`
	// +optional
	OperationsPort int `json:"operationsPort"`
	// +optional
	AdminPort int `json:"adminPort"`
	// +optional
	NodePort int `json:"port"`
	// +optional
	Message string `json:"message"`
}

type Cors struct {
	// +kubebuilder:default:=false
	Enabled bool     `json:"enabled"`
	Origins []string `json:"origins"`
}
type FabricCADatabase struct {
	Type       string `json:"type"`
	Datasource string `json:"datasource"`
}

// FabricCASpec defines the desired state of FabricCA
type FabricCASpec struct {
	// +optional
	// +nullable
	ServiceMonitor *ServiceMonitor `json:"serviceMonitor"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Istio    *FabricIstio     `json:"istio"`
	Database FabricCADatabase `json:"db"`
	// +kubebuilder:validation:MinItems=1
	// Hosts for the Fabric CA
	Hosts   []string            `json:"hosts"`
	Service FabricCASpecService `json:"service"`
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`
	// +kubebuilder:validation:MinLength=1
	Version string `json:"version"`
	// +kubebuilder:default:=false
	Debug bool `json:"debug"`
	// +kubebuilder:default:=512000
	CLRSizeLimit int              `json:"clrSizeLimit"`
	TLS          FabricCATLSConf  `json:"rootCA"`
	CA           FabricCAItemConf `json:"ca"`
	TLSCA        FabricCAItemConf `json:"tlsCA"`
	Cors         Cors             `json:"cors"`

	Resources corev1.ResourceRequirements `json:"resources"`
	Storage   Storage                     `json:"storage"`
	Metrics   FabricCAMetrics             `json:"metrics"`
}

type FabricCATLSConf struct {
	Subject FabricCASubject `json:"subject"`
}
type FabricCACFG struct {
	Identities   FabricCACFGIdentities  `json:"identities"`
	Affiliations FabricCACFGAffilitions `json:"affiliations"`
}
type FabricCACFGIdentities struct {
	// +kubebuilder:default:=true
	AllowRemove bool `json:"allowRemove"`
}
type FabricCACFGAffilitions struct {
	// +kubebuilder:default:=true
	AllowRemove bool `json:"allowRemove"`
}
type FabricCAMetrics struct {
	// +kubebuilder:default:="disabled"
	Provider string `json:"provider"`
	// +optional
	Statsd *FabricCAMetricsStatsd `json:"statsd"`
}
type FabricCAMetricsStatsd struct {
	// +kubebuilder:validation:Enum=udp;tcp
	// +kubebuilder:default:="udp"
	Network string `json:"network"`
	// +optional
	Address string `json:"address"`
	// +optional
	// +kubebuilder:default:="10s"
	WriteInterval string `json:"writeInterval"`
	// +optional
	// +kubebuilder:default:=""
	Prefix string `json:"prefix"`
}

// +kubebuilder:validation:Enum=statsd;prometheus;disabled
type MetricsProvider string

type Storage struct {
	// +kubebuilder:default:="5Gi"
	Size string `json:"size"`
	// +kubebuilder:default:=""
	// +optional
	StorageClass string `json:"storageClass"`
	// +kubebuilder:default:="ReadWriteOnce"
	AccessMode corev1.PersistentVolumeAccessMode `json:"accessMode"`
}

type FabricCAItemConf struct {
	Name         string               `json:"name"`
	CFG          FabricCACFG          `json:"cfg"`
	Subject      FabricCASubject      `json:"subject"`
	CSR          FabricCACSR          `json:"csr"`
	CRL          FabricCACRL          `json:"crl"`
	Registry     FabricCARegistry     `json:"registry"`
	Intermediate FabricCAIntermediate `json:"intermediate"`
	BCCSP        FabricCABCCSP        `json:"bccsp"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	CA *FabricCACrypto `json:"ca"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	TlsCA *FabricTLSCACrypto `json:"tlsCa"`
}
type FabricTLSCACrypto struct {
	Key        string             `json:"key"`
	Cert       string             `json:"cert"`
	ClientAuth FabricCAClientAuth `json:"clientAuth"`
}
type FabricCAClientAuth struct {
	// NoClientCert, RequestClientCert, RequireAnyClientCert, VerifyClientCertIfGiven and RequireAndVerifyClientCert.
	Type     string   `json:"type"`
	CertFile []string `json:"cert_file"`
}
type FabricCACrypto struct {
	Key   string `json:"key"`
	Cert  string `json:"cert"`
	Chain string `json:"chain"`
}
type FabricCASubject struct {
	// +kubebuilder:default:="ca"
	CN string `json:"cn"`
	// +kubebuilder:default:="US"
	C string `json:"C"`
	// +kubebuilder:default:="North Carolina"
	ST string `json:"ST"`
	// +kubebuilder:default:="Hyperledger"
	O string `json:"O"`
	// +kubebuilder:default:="Raleigh"
	L string `json:"L"`
	// +kubebuilder:default:="Fabric"
	OU string `json:"OU"`
}
type FabricCABCCSP struct {
	// +kubebuilder:default:="SW"
	Default string          `json:"default"`
	SW      FabricCABCCSPSW `json:"sw"`
}
type FabricCABCCSPSW struct {
	// +kubebuilder:default:="SHA2"
	Hash string `json:"hash"`
	// +kubebuilder:default:="256"
	Security string `json:"security"`
}

type FabricCAIntermediate struct {
	ParentServer FabricCAIntermediateParentServer `json:"parentServer"`
}
type FabricCAIntermediateParentServer struct {
	URL    string `json:"url"`
	CAName string `json:"caName"`
}
type FabricCAIntermediateEnrollment struct {
	Hosts   string `json:"hosts"`
	Profile string `json:"profile"`
	Label   string `json:"label"`
}
type FabricCAIntermediateTLS struct {
	CertFiles []string                      `json:"certFiles"`
	Client    FabricCAIntermediateTLSClient `json:"client"`
}
type FabricCAIntermediateTLSClient struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}
type FabricCARegistry struct {
	MaxEnrollments int                `json:"max_enrollments"`
	Identities     []FabricCAIdentity `json:"identities"`
}
type FabricCAIdentity struct {
	Name string `json:"name"`
	Pass string `json:"pass"`
	Type string `json:"type"`
	// +kubebuilder:default:=""
	Affiliation string                `json:"affiliation"`
	Attrs       FabricCAIdentityAttrs `json:"attrs"`
}
type FabricCAIdentityAttrs struct {
	// +kubebuilder:default:="*"
	RegistrarRoles string `json:"hf.Registrar.Roles"`
	// +kubebuilder:default:="*"
	DelegateRoles string `json:"hf.Registrar.DelegateRoles"`
	// +kubebuilder:default:="*"
	Attributes string `json:"hf.Registrar.Attributes"`
	// +kubebuilder:default:=true
	Revoker bool `json:"hf.Revoker"`
	// +kubebuilder:default:=true
	IntermediateCA bool `json:"hf.IntermediateCA"`
	// +kubebuilder:default:=true
	GenCRL bool `json:"hf.GenCRL"`
	// +kubebuilder:default:=true
	AffiliationMgr bool `json:"hf.AffiliationMgr"`
}
type FabricCACRL struct {
	// +kubebuilder:default:="24h"
	Expiry string `json:"expiry"`
}
type FabricCACSR struct {
	// +kubebuilder:default:="ca"
	CN string `json:"cn"`
	// +kubebuilder:default:={"localhost"}
	Hosts []string        `json:"hosts"`
	Names []FabricCANames `json:"names"`
	CA    FabricCACSRCA   `json:"ca"`
}
type FabricCACSRCA struct {
	// +kubebuilder:default:="131400h"
	Expiry string `json:"expiry"`
	// +kubebuilder:default:=0
	PathLength int `json:"pathLength"`
}
type FabricCANames struct {
	// +kubebuilder:default:="US"
	C string `json:"C"`
	// +kubebuilder:default:="North Carolina"
	ST string `json:"ST"`
	// +kubebuilder:default:="Hyperledger"
	O string `json:"O"`
	// +kubebuilder:default:="Raleigh"
	L string `json:"L"`
	// +kubebuilder:default:="Fabric"
	OU string `json:"OU"`
}
type FabricCASpecService struct {
	ServiceType corev1.ServiceType `json:"type"`
}
type DeploymentStatus string

const (
	PendingStatus        DeploymentStatus = "PENDING"
	FailedStatus         DeploymentStatus = "FAILED"
	RunningStatus        DeploymentStatus = "RUNNING"
	UnknownStatus        DeploymentStatus = "UNKNOWN"
	UpdatingVersion      DeploymentStatus = "UPDATING_VERSION"
	UpdatingCertificates DeploymentStatus = "UPDATING_CERTIFICATES"
)

// FabricCAStatus defines the observed state of FabricCA
type FabricCAStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`

	// +optional
	NodePort int `json:"nodePort"`
	// TLS Certificate to connect to the FabricCA
	TlsCert string `json:"tls_cert"`
	// Root certificate for Sign certificates generated by FabricCA
	CACert string `json:"ca_cert"`
	// Root certificate for TLS certificates generated by FabricCA
	TLSCACert string `json:"tlsca_cert"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=peer,singular=peer
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// FabricPeer is the Schema for the hlfs API
type FabricPeer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FabricPeerSpec   `json:"spec,omitempty"`
	Status FabricPeerStatus `json:"status,omitempty"`
}

func (in *FabricPeer) FullName() string {
	return fmt.Sprintf("%s.%s", in.Name, in.Namespace)
}

// +kubebuilder:object:root=true

// FabricPeerList contains a list of FabricPeer
type FabricPeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricPeer `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=orderingservice,singular=orderingservice
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// FabricOrderingService is the Schema for the hlfs API
type FabricOrderingService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FabricOrderingServiceSpec   `json:"spec,omitempty"`
	Status FabricOrderingServiceStatus `json:"status,omitempty"`
}

func (s *FabricOrderingService) FullName() string {
	return fmt.Sprintf("%s.%s", s.Name, s.Namespace)
}

// +kubebuilder:object:root=true

// FabricOrderingServiceList contains a list of FabricOrderingService
type FabricOrderingServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricOrderingService `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=orderernode,singular=orderernode
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// FabricOrdererNode is the Schema for the hlfs API
type FabricOrdererNode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FabricOrdererNodeSpec   `json:"spec,omitempty"`
	Status FabricOrdererNodeStatus `json:"status,omitempty"`
}

func (n *FabricOrdererNode) FullName() string {
	return fmt.Sprintf("%s.%s", n.Name, n.Namespace)
}

// +kubebuilder:object:root=true

// FabricOrdererNodeList contains a list of FabricOrdererNode
type FabricOrdererNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricOrdererNode `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ca,singular=ca
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricCA is the Schema for the hlfs API
type FabricCA struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricCASpec   `json:"spec,omitempty"`
	Status            FabricCAStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricCAList contains a list of FabricCA
type FabricCAList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricCA `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FabricPeer{}, &FabricPeerList{})
	SchemeBuilder.Register(&FabricOrderingService{}, &FabricOrderingServiceList{})
	SchemeBuilder.Register(&FabricCA{}, &FabricCAList{})
	SchemeBuilder.Register(&FabricOrdererNode{}, &FabricOrdererNodeList{})
}
