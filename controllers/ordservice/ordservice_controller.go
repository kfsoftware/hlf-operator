package ordservice

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"github.com/kfsoftware/hlf-operator/controllers/testutils"
	operatorv1 "github.com/kfsoftware/hlf-operator/pkg/client/clientset/versioned"
	"github.com/operator-framework/operator-lib/status"
	"helm.sh/helm/v3/pkg/cli"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/go-logr/logr"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/api/hlf.kungfusoftware.es/v1alpha1"
	"github.com/kfsoftware/hlf-operator/controllers/certs"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	log "github.com/sirupsen/logrus"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/storage/driver"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// FabricOrderingServiceReconciler reconciles a FabricOrderingService object
type FabricOrderingServiceReconciler struct {
	client.Client
	ChartPath string
	Log       logr.Logger
	Scheme    *runtime.Scheme
	Config    *rest.Config
}

func getOrdererName(chartName string, idx int) string {
	return fmt.Sprintf("%s--ord-%d-hlf-ordnode", chartName, idx)
}
func getExistingTLSCrypto(client *kubernetes.Clientset, chartName string, namespace string, idx int) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	baseName := getOrdererName(chartName, idx)
	secretName := fmt.Sprintf("%s-tls", baseName)
	tlsRootSecretName := fmt.Sprintf("%s-tlsrootcert", baseName)
	secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, v1.GetOptions{})
	if err != nil {
		return nil, nil, nil, err
	}
	rootCertSecret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), tlsRootSecretName, v1.GetOptions{})
	if err != nil {
		return nil, nil, nil, err
	}
	// cacert.pem
	tlsKeyData := secret.Data["tls.key"]
	tlsCrtData := secret.Data["tls.crt"]
	rootTLSCrtData := rootCertSecret.Data["cacert.pem"]
	key, err := utils.ParseECDSAPrivateKey(tlsKeyData)
	if err != nil {
		return nil, nil, nil, err
	}
	crt, err := utils.ParseX509Certificate(tlsCrtData)
	if err != nil {
		return nil, nil, nil, err
	}
	rootCrt, err := utils.ParseX509Certificate(rootTLSCrtData)
	if err != nil {
		return nil, nil, nil, err
	}
	return crt, key, rootCrt, nil
}

func getExistingSignCrypto(client *kubernetes.Clientset, chartName string, namespace string, idx int) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	baseName := getOrdererName(chartName, idx)
	secretCrtName := fmt.Sprintf("%s-idcert", baseName)
	secretKeyName := fmt.Sprintf("%s-idkey", baseName)
	secretRootCrtName := fmt.Sprintf("%s-cacert", baseName)

	secretCrt, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secretCrtName, v1.GetOptions{})
	if err != nil {
		return nil, nil, nil, err
	}
	secretKey, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secretKeyName, v1.GetOptions{})
	if err != nil {
		return nil, nil, nil, err
	}
	secretRootCrt, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secretRootCrtName, v1.GetOptions{})
	if err != nil {
		return nil, nil, nil, err
	}
	signCrtData := secretCrt.Data["cert.pem"]
	signKeyData := secretKey.Data["key.pem"]
	signRootCrtData := secretRootCrt.Data["cacert.pem"]
	crt, err := utils.ParseX509Certificate(signCrtData)
	if err != nil {
		return nil, nil, nil, err
	}
	rootCrt, err := utils.ParseX509Certificate(signRootCrtData)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := utils.ParseECDSAPrivateKey(signKeyData)
	if err != nil {
		return nil, nil, nil, err
	}
	return crt, key, rootCrt, nil
}

func getConfig(conf *hlfv1alpha1.FabricOrderingService, client *kubernetes.Clientset) (*FabricOrdChart, error) {
	spec := conf.Spec
	signCertStr, err := base64.StdEncoding.DecodeString(conf.Spec.Enrollment.Component.Catls.Cacert)
	if err != nil {
		return nil, err
	}
	signCAInfo, err := certs.GetCAInfo(certs.GetCAInfoRequest{
		TLSCert: string(signCertStr),
		URL: fmt.Sprintf(
			"https://%s:%d",
			conf.Spec.Enrollment.Component.Cahost,
			conf.Spec.Enrollment.Component.Caport,
		),
		Name:  conf.Spec.Enrollment.Component.Caname,
		MSPID: conf.Spec.MspID,
	})
	if err != nil {
		return nil, err
	}
	tlsCertStr, err := base64.StdEncoding.DecodeString(conf.Spec.Enrollment.TLS.Catls.Cacert)
	if err != nil {
		return nil, err
	}
	tlsCAInfo, err := certs.GetCAInfo(certs.GetCAInfoRequest{
		TLSCert: string(tlsCertStr),
		URL: fmt.Sprintf(
			"https://%s:%d",
			conf.Spec.Enrollment.TLS.Cahost,
			conf.Spec.Enrollment.TLS.Caport,
		),
		Name:  conf.Spec.Enrollment.TLS.Caname,
		MSPID: conf.Spec.MspID,
	})
	if err != nil {
		return nil, err
	}
	tlsCAPem := string(tlsCAInfo.CAChain)
	signCAPem := string(signCAInfo.CAChain)
	ordererNodes := []testutils.OrdererNode{}
	publicIP, err := utils.GetPublicIPKubernetes(client)
	if err != nil {
		return nil, err
	}
	var fabricOrdChart FabricOrdChart
	numNodes := len(spec.Nodes)
	nodePorts, err := utils.GetFreeNodeports(publicIP, numNodes)
	if err != nil {
		return nil, err
	}
	nodes := []Node{}
	for nodeIdx, node := range spec.Nodes {
		tlsHosts := []string{}
		for _, host := range node.Enrollment.TLS.Csr.Hosts {
			tlsHosts = append(tlsHosts, host)
		}
		if !utils.Contains(tlsHosts, publicIP) {
			tlsHosts = append(tlsHosts, publicIP)
		}
		tlsCertPEM, err := base64.StdEncoding.DecodeString(conf.Spec.Enrollment.TLS.Catls.Cacert)
		if err != nil {
			return nil, err
		}

		tlsCert, tlsKey, tlsRootCert, err := certs.EnrollUser(certs.EnrollUserRequest{
			TLSCert: string(tlsCertPEM),
			URL: fmt.Sprintf(
				"https://%s:%d",
				conf.Spec.Enrollment.TLS.Cahost,
				conf.Spec.Enrollment.TLS.Caport,
			),
			Name:       conf.Spec.Enrollment.TLS.Caname,
			MSPID:      conf.Spec.MspID,
			User:       conf.Spec.Enrollment.TLS.Enrollid,
			Secret:     conf.Spec.Enrollment.TLS.Enrollsecret,
			Hosts:      tlsHosts,
			CN:         "",
			Profile:    "tls",
			Attributes: nil,
		})
		if err != nil {
			return nil, err
		}
		componentCertPEM, err := base64.StdEncoding.DecodeString(conf.Spec.Enrollment.Component.Catls.Cacert)
		if err != nil {
			return nil, err
		}
		signCert, signKey, signRootCert, err := certs.EnrollUser(certs.EnrollUserRequest{
			TLSCert: string(componentCertPEM),
			URL: fmt.Sprintf(
				"https://%s:%d",
				conf.Spec.Enrollment.Component.Cahost,
				conf.Spec.Enrollment.Component.Caport,
			),
			Name:       conf.Spec.Enrollment.Component.Caname,
			MSPID:      conf.Spec.MspID,
			User:       conf.Spec.Enrollment.Component.Enrollid,
			Secret:     conf.Spec.Enrollment.Component.Enrollsecret,
			Profile:    "",
			Attributes: nil,
		})
		if err != nil {
			return nil, err
		}

		requestNodePort := nodePorts[nodeIdx]
		ingressHosts := []string{}
		if node.Host != "" {
			ingressHosts = append(ingressHosts, node.Host)
		}
		signCRTEncoded := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: signCert.Raw,
		})
		signRootCRTEncoded := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: signRootCert.Raw,
		})
		signEncodedPK, err := x509.MarshalPKCS8PrivateKey(signKey)
		if err != nil {
			return nil, err
		}
		signPEMEncodedPK := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: signEncodedPK,
		})

		tlsCRTEncoded := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: tlsCert.Raw,
		})
		tlsRootCRTEncoded := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: tlsRootCert.Raw,
		})
		tlsEncodedPK, err := x509.MarshalPKCS8PrivateKey(tlsKey)
		if err != nil {
			return nil, err
		}
		tlsPEMEncodedPK := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: tlsEncodedPK,
		})
		host := publicIP
		if node.Host != "" {
			host = node.Host
		}
		port := requestNodePort
		if node.Port != 0 {
			port = node.Port
		}
		ordererNodes = append(ordererNodes, testutils.OrdererNode{
			TLSCert: string(utils.EncodeX509Certificate(tlsCert)),
			Host:    host,
			Port:    port,
		})
		nodes = append(nodes, Node{
			SignKey:      string(signPEMEncodedPK),
			SignCert:     string(signCRTEncoded),
			SignRootCert: string(signRootCRTEncoded),
			TLSCert:      string(tlsCRTEncoded),
			TLSKey:       string(tlsPEMEncodedPK),
			TLSRootCert:  string(tlsRootCRTEncoded),
			Hosts:        ingressHosts,
			Service: Service{
				Type:            string(spec.Service.Type),
				NodePortRequest: requestNodePort,
			},
		})
	}
	channelConfig := spec.SystemChannel.Config
	batchTimeout, err := time.ParseDuration(channelConfig.BatchTimeout)
	if err != nil {
		return nil, err
	}
	_, err = time.ParseDuration(channelConfig.TickInterval)
	if err != nil {
		return nil, err
	}
	genesisConfig := testutils.GenesisConfig{
		BatchTimeout:      batchTimeout,
		MaxMessageCount:   channelConfig.MaxMessageCount,
		AbsoluteMaxBytes:  channelConfig.AbsoluteMaxBytes,
		PreferredMaxBytes: channelConfig.PreferredMaxBytes,
		OrdererCapabilities: testutils.OrdererCapabilities{
			V2_0: channelConfig.OrdererCapabilities.V2_0,
		},
		ApplicationCapabilities: testutils.ApplicationCapabilities{
			V2_0: channelConfig.ApplicationCapabilities.V2_0,
		},
		ChannelCapabilities: testutils.ChannelCapabilities{
			V2_0: channelConfig.ChannelCapabilities.V2_0,
		},
		SnapshotIntervalSize: channelConfig.SnapshotIntervalSize,
		TickInterval:         channelConfig.TickInterval,
		ElectionTick:         channelConfig.ElectionTick,
		HeartbeatTick:        channelConfig.HeartbeatTick,
		MaxInflightBlocks:    channelConfig.MaxInflightBlocks,
	}
	profileConfig, err := testutils.GetProfileConfig(
		[]testutils.OrdererOrganization{
			{
				Nodes:        ordererNodes,
				RootTLSCert:  tlsCAPem,
				RootSignCert: signCAPem,
				MspID:        conf.Spec.MspID,
			},
		},
		genesisConfig,
	)
	if err != nil {
		return nil, err
	}
	genesisBytes, err := resource.CreateGenesisBlockForOrderer(profileConfig, spec.SystemChannel.Name)
	if err != nil {
		return nil, err
	}
	genesisB64 := base64.StdEncoding.EncodeToString(genesisBytes)

	fabricOrdChart = FabricOrdChart{
		FullNameOverride: conf.Name,
		Image: Image{
			Repository: spec.Image,
			Tag:        spec.Tag,
			PullPolicy: "IfNotPresent",
		},
		Genesis: genesisB64,
		Storage: Storage{
			Size:         spec.Storage.Size,
			AccessMode:   string(spec.Storage.AccessMode),
			StorageClass: spec.Storage.StorageClass,
		},
		MspID: spec.MspID,
		Nodes: nodes,
	}

	return &fabricOrdChart, nil
}

const ordererFinalizer = "finalizer.orderer.hlf.kungfusoftware.es"

func (r *FabricOrderingServiceReconciler) finalizeOrderer(reqLogger logr.Logger, m *hlfv1alpha1.FabricOrderingService) error {
	ns := m.Namespace
	if ns == "" {
		ns = "default"
	}
	cfg, err := newActionCfg(r.Log, r.Config, ns)
	if err != nil {
		return err
	}
	releaseName := m.Name
	reqLogger.Info("Successfully finalized orderer")
	cmd := action.NewUninstall(cfg)
	resp, err := cmd.Run(releaseName)
	if err != nil {
		if strings.Compare("Release not loaded", err.Error()) != 0 {
			return nil
		}
		return err
	}
	log.Debugf("Release %s deleted=%s", releaseName, resp.Info)
	return nil
}

func (r *FabricOrderingServiceReconciler) addFinalizer(reqLogger logr.Logger, m *hlfv1alpha1.FabricOrderingService) error {
	reqLogger.Info("Adding Finalizer for the Orderer")
	controllerutil.AddFinalizer(m, ordererFinalizer)

	// Update CR
	err := r.Update(context.TODO(), m)
	if err != nil {
		reqLogger.Error(err, "Failed to update Orderer with finalizer")
		return err
	}
	return nil
}

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderingservices,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderingservices/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderingservices/finalizers,verbs=get;update;patch
func (r *FabricOrderingServiceReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	reqLogger := r.Log.WithValues("hlf", req.NamespacedName)
	fabricOrderer := &hlfv1alpha1.FabricOrderingService{}
	releaseName := req.Name
	ns := req.Namespace
	cfg, err := newActionCfg(r.Log, r.Config, ns)
	if err != nil {
		return ctrl.Result{}, err
	}
	err = r.Get(ctx, req.NamespacedName, fabricOrderer)
	if err != nil {
		log.Debugf("Error getting the object %s error=%v", req.NamespacedName, err)
		if apierrors.IsNotFound(err) {
			reqLogger.Info("Orderer resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		reqLogger.Error(err, "Failed to get Orderer.")
		return ctrl.Result{}, err
	}
	isMemcachedMarkedToBeDeleted := fabricOrderer.GetDeletionTimestamp() != nil
	if isMemcachedMarkedToBeDeleted {
		if utils.Contains(fabricOrderer.GetFinalizers(), ordererFinalizer) {
			if err := r.finalizeOrderer(reqLogger, fabricOrderer); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(fabricOrderer, ordererFinalizer)
			err := r.Update(ctx, fabricOrderer)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	if !utils.Contains(fabricOrderer.GetFinalizers(), ordererFinalizer) {
		if err := r.addFinalizer(reqLogger, fabricOrderer); err != nil {
			return ctrl.Result{}, err
		}
	}
	cmdStatus := action.NewStatus(cfg)
	exists := true
	_, err = cmdStatus.Run(releaseName)
	if err != nil {
		if errors.Is(err, driver.ErrReleaseNotFound) {
			// it doesn't exists
			exists = false
		} else {
			// it doesnt exist
			return ctrl.Result{}, err
		}
	}
	log.Debugf("Release %s exists=%v", releaseName, exists)
	clientSet, err := utils.GetClientKubeWithConf(r.Config)
	if err != nil {
		return ctrl.Result{}, err
	}
	if exists {
		// update
		s, err := getOrdererState(r.Config, releaseName, ns)
		if err != nil {
			return ctrl.Result{}, err
		}
		fOrderer := fabricOrderer.DeepCopy()
		fOrderer.Status.Status = s.Status
		fOrderer.Status.Conditions.SetCondition(status.Condition{
			Type:   status.ConditionType(s.Status),
			Status: "True",
		})
		if reflect.DeepEqual(fOrderer.Status, fabricOrderer.Status) {
			log.Infof("Status hasn't changed, skipping update")
		} else {
			cmd := action.NewUpgrade(cfg)
			cmd.MaxHistory = 5
			err = os.Setenv("HELM_NAMESPACE", req.Namespace)
			if err != nil {
				return ctrl.Result{}, err
			}
			settings := cli.New()
			chartPath, err := cmd.LocateChart(r.ChartPath, settings)
			ch, err := loader.Load(chartPath)
			if err != nil {
				return ctrl.Result{}, err
			}
			c, err := getConfig(fabricOrderer, clientSet)
			if err != nil {
				return ctrl.Result{}, err
			}
			inrec, err := json.Marshal(c)
			if err != nil {
				return ctrl.Result{}, err
			}
			var inInterface map[string]interface{}
			err = json.Unmarshal(inrec, &inInterface)

			if err != nil {
				return ctrl.Result{}, err
			}
			release, err := cmd.Run(releaseName, ch, inInterface)
			if err != nil {
				return ctrl.Result{}, err
			}
			log.Debugf("Chart upgraded %s", release.Name)
			if err := r.Status().Update(ctx, fOrderer); err != nil {
				log.Debugf("Error updating the status: %v", err)
				return ctrl.Result{}, err
			}
		}

		if s.Status == hlfv1alpha1.RunningStatus {
			return ctrl.Result{
				//RequeueAfter: 120 * time.Second,
			}, nil
		} else {
			return ctrl.Result{
				RequeueAfter: 2 * time.Second,
			}, nil
		}
	} else {
		cmd := action.NewInstall(cfg)
		name, chart, err := cmd.NameAndChart([]string{releaseName, r.ChartPath})
		if err != nil {
			return ctrl.Result{}, err
		}

		cmd.ReleaseName = name
		ch, err := loader.Load(chart)
		if err != nil {
			return ctrl.Result{}, err
		}
		c, err := getConfig(fabricOrderer, clientSet)
		if err != nil {
			reqLogger.Error(err, "Failed to get config for orderer %s/%s", req.Namespace, req.Name)
			return ctrl.Result{}, err
		}
		var inInterface map[string]interface{}
		inrec, err := json.Marshal(c)
		if err != nil {
			return ctrl.Result{}, err
		}
		log.Debugf(string(inrec))
		err = json.Unmarshal(inrec, &inInterface)
		if err != nil {
			return ctrl.Result{}, err
		}
		release, err := cmd.Run(ch, inInterface)
		if err != nil {
			reqLogger.Info(fmt.Sprintf("Failed to install chart %v", err))
			return ctrl.Result{}, err
		}
		reqLogger.Info(fmt.Sprintf("Chart installed %s", release.Name))
		fabricOrderer.Status.Status = hlfv1alpha1.PendingStatus
		fabricOrderer.Status.Conditions.SetCondition(status.Condition{
			Type:   "DEPLOYED",
			Status: "True",
		})
		if err := r.Status().Update(ctx, fabricOrderer); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{
			Requeue:      false,
			RequeueAfter: 10 * time.Second,
		}, nil
	}
}

func (r *FabricOrderingServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hlfv1alpha1.FabricOrderingService{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}

func newActionCfg(log logr.Logger, clusterCfg *rest.Config, namespace string) (*action.Configuration, error) {
	err := os.Setenv("HELM_NAMESPACE", namespace)
	if err != nil {
		return nil, err
	}
	cfg := new(action.Configuration)
	ns := namespace
	err = cfg.Init(&genericclioptions.ConfigFlags{
		Namespace:   &ns,
		APIServer:   &clusterCfg.Host,
		CAFile:      &clusterCfg.CAFile,
		BearerToken: &clusterCfg.BearerToken,
	}, ns, "secret", actionLogger(log))
	return cfg, err
}

func actionLogger(logger logr.Logger) func(format string, v ...interface{}) {
	return func(format string, v ...interface{}) {
		logger.Info(fmt.Sprintf(format, v...))
	}
}

type OrdererStatus struct {
	Status hlfv1alpha1.DeploymentStatus
}

func getOrdererState(config *rest.Config, releaseName string, ns string) (*OrdererStatus, error) {
	ctx := context.Background()
	r := &OrdererStatus{
		Status: hlfv1alpha1.RunningStatus,
	}
	clientSet, err := operatorv1.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	ordererNodes, err := clientSet.HlfV1alpha1().FabricOrdererNodes(ns).List(ctx, v1.ListOptions{
		LabelSelector: fmt.Sprintf("release=%s", releaseName),
	})
	if err != nil {
		return nil, err
	}
	for _, ordererNode := range ordererNodes.Items {
		if ordererNode.Status.Status != hlfv1alpha1.RunningStatus {
			r.Status = ordererNode.Status.Status
			break
		}
	}
	return r, nil
}
