package peer

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/kfsoftware/hlf-operator/controllers/hlfmetrics"
	"k8s.io/apimachinery/pkg/types"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/operator-framework/operator-lib/status"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"helm.sh/helm/v3/pkg/cli"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/pkg/api/v1/pod"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/go-logr/logr"
	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/api/hlf.kungfusoftware.es/v1alpha1"
	"github.com/kfsoftware/hlf-operator/controllers/certs"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/storage/driver"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FabricPeerReconciler reconciles a FabricPeer object
type FabricPeerReconciler struct {
	client.Client
	ChartPath string
	Log       logr.Logger
	Scheme    *runtime.Scheme
	Config    *rest.Config
}

func (r *FabricPeerReconciler) addFinalizer(reqLogger logr.Logger, m *hlfv1alpha1.FabricPeer) error {
	if len(m.GetFinalizers()) < 1 && m.GetDeletionTimestamp() == nil {
		reqLogger.Info("Adding Finalizer for the Memcached")
		m.SetFinalizers([]string{peerFinalizer})
		// Update CR
		err := r.Client.Update(context.TODO(), m)
		if err != nil {
			reqLogger.Error(err, "Failed to update Peer with finalizer")
			return err
		}
		reqLogger.Info(fmt.Sprintf("Finalizer for peer %s added", m.Name))
	}
	return nil
}

type Status struct {
	Status   hlfv1alpha1.DeploymentStatus
	TLSCert  string
	NodePort int
}

const (
	deploymentRestartTriggerAnnotation = "es.kungfusoftware.hlf.deployment-restart.timestamp"
)

func restartDeployment(config *rest.Config, deployment *appsv1.Deployment) error {
	clientSet, err := utils.GetClientKubeWithConf(config)
	if err != nil {
		return err
	}

	patchData := map[string]interface{}{}
	patchData["spec"] = map[string]interface{}{
		"template": map[string]interface{}{
			"metadata": map[string]interface{}{
				"annotations": map[string]interface{}{
					deploymentRestartTriggerAnnotation: time.Now().Format(time.Stamp),
				},
			},
		},
	}
	encodedData, err := json.Marshal(patchData)
	if err != nil {
		return err
	}
	_, err = clientSet.AppsV1().Deployments(deployment.Namespace).Patch(context.TODO(), deployment.Name, types.MergePatchType, encodedData, v1.PatchOptions{})
	if err != nil {
		return err
	}
	return nil
}
func GetPeerDeployment(conf *action.Configuration, config *rest.Config, releaseName string, ns string, ) (*appsv1.Deployment, error, ) {
	ctx := context.Background()
	cmd := action.NewGet(conf)
	rel, err := cmd.Run(releaseName)
	if err != nil {
		return nil, err
	}
	clientSet, err := utils.GetClientKubeWithConf(config)
	if err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	objects := utils.ParseK8sYaml([]byte(rel.Manifest))
	for _, object := range objects {
		kind := object.GetObjectKind().GroupVersionKind().Kind
		if kind == "Deployment" {
			depSpec := object.(*appsv1.Deployment)
			dep, err := clientSet.AppsV1().Deployments(ns).Get(ctx, depSpec.Name, v1.GetOptions{})
			if err != nil {
				return nil, err
			}
			return dep, nil
		}
	}
	return nil, errors.Errorf("Deployment not found")

}
func GetPeerState(conf *action.Configuration, config *rest.Config, releaseName string, ns string, svc *corev1.Service) (*hlfv1alpha1.FabricPeerStatus, error) {
	ctx := context.Background()
	cmd := action.NewGet(conf)
	rel, err := cmd.Run(releaseName)
	if err != nil {
		return nil, err
	}
	clientSet, err := utils.GetClientKubeWithConf(config)
	if err != nil {
		return nil, err
	}
	if ns == "" {
		ns = "default"
	}
	r := &hlfv1alpha1.FabricPeerStatus{
		Status: hlfv1alpha1.PendingStatus,
	}
	objects := utils.ParseK8sYaml([]byte(rel.Manifest))
	for _, object := range objects {
		kind := object.GetObjectKind().GroupVersionKind().Kind
		if kind == "Deployment" {
			depSpec := object.(*appsv1.Deployment)
			dep, err := clientSet.AppsV1().Deployments(ns).Get(ctx, depSpec.Name, v1.GetOptions{})
			if err != nil {
				return nil, err
			}
			pods, err := clientSet.CoreV1().Pods(ns).List(ctx, v1.ListOptions{
				LabelSelector: fmt.Sprintf("release=%s", releaseName),
			})
			if err != nil {
				return nil, err
			}
			if len(pods.Items) > 0 {
				for _, item := range pods.Items {
					if pod.IsPodReadyConditionTrue(item.Status) {
						r.Status = hlfv1alpha1.RunningStatus
					} else {
						switch item.Status.Phase {
						case corev1.PodPending:
							r.Status = hlfv1alpha1.PendingStatus
						case corev1.PodSucceeded:
						case corev1.PodRunning:
							r.Status = hlfv1alpha1.RunningStatus
						case corev1.PodFailed:
							r.Status = hlfv1alpha1.FailedStatus
						case corev1.PodUnknown:
							r.Status = hlfv1alpha1.UnknownStatus
						}
					}
				}
			} else {
				if dep.Status.ReadyReplicas == *depSpec.Spec.Replicas {
					r.Status = hlfv1alpha1.RunningStatus
				} else {
					r.Status = hlfv1alpha1.PendingStatus
				}
			}
		}
	}
	for _, port := range svc.Spec.Ports {
		if port.Name == PeerPortName {
			r.NodePort = int(port.NodePort)
		}
	}

	tlsCrt, _, rootTlsCrt, err := getExistingTLSCrypto(clientSet, releaseName, ns)
	if err != nil {
		return nil, err
	}
	r.TlsCert = string(utils.EncodeX509Certificate(tlsCrt))
	r.TlsCACert = string(utils.EncodeX509Certificate(rootTlsCrt))
	hlfmetrics.UpdateCertificateExpiry(
		"peer",
		"tls",
		tlsCrt,
		releaseName,
		ns,
	)
	signCrt, _, rootSignCrt, err := getExistingSignCrypto(clientSet, releaseName, ns)
	if err != nil {
		return nil, err
	}
	r.SignCert = string(utils.EncodeX509Certificate(signCrt))
	r.SignCACert = string(utils.EncodeX509Certificate(rootSignCrt))
	hlfmetrics.UpdateCertificateExpiry(
		"peer",
		"sign",
		signCrt,
		releaseName,
		ns,
	)
	return r, nil
}

const peerFinalizer = "finalizer.peer.hlf.kungfusoftware.es"

const chartName = "hlf-peer"

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricpeers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricpeers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricpeers/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderernodes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderernodes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderernodes/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderingservices,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderingservices/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabricorderingservices/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabriccas,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabriccas/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hlf.kungfusoftware.es,resources=fabriccas/finalizers,verbs=get;update;patch

// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=deployments,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=replicasets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=replicasets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=replicasets,verbs=get;list;watch;create;update;patch;delete


// +kubebuilder:rbac:groups=apps,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=pods,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=pods,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=services,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=secrets,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=pods/log,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=pods/log,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=pods/status,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods/status,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=pods/status,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=apps,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=extensions,resources=configmaps,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=networking.istio.io,resources=gateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.istio.io,resources=virtualservices,verbs=get;list;watch;create;update;patch;delete

func (r *FabricPeerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	reqLogger := r.Log.WithValues("hlf", req.NamespacedName)
	fabricPeer := &hlfv1alpha1.FabricPeer{}
	releaseName := req.Name
	ns := req.Namespace
	cfg, err := newActionCfg(r.Log, r.Config, ns)
	if err != nil {
		r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
	}
	err = r.Get(ctx, req.NamespacedName, fabricPeer)
	if err != nil {
		log.Debugf("Error getting the object %s error=%v", req.NamespacedName, err)
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Info("Peer resource not found. Ignoring since object must be deleted.")

			return ctrl.Result{}, nil
		}
		reqLogger.Error(err, "Failed to get Peer.")
		r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
	}

	isPeerMarkedToDelete := fabricPeer.GetDeletionTimestamp() != nil
	if isPeerMarkedToDelete {
		if utils.Contains(fabricPeer.GetFinalizers(), peerFinalizer) {
			if err := r.finalizePeer(reqLogger, fabricPeer); err != nil {
				r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
				return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
			}
			controllerutil.RemoveFinalizer(fabricPeer, peerFinalizer)
			err := r.Update(ctx, fabricPeer)
			if err != nil {
				r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
				return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
			}
		}
		return ctrl.Result{}, nil
	}
	if !utils.Contains(fabricPeer.GetFinalizers(), peerFinalizer) {
		if err := r.addFinalizer(reqLogger, fabricPeer); err != nil {
			r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
		}
	}

	cmdStatus := action.NewStatus(cfg)
	exists := true
	_, err = cmdStatus.Run(releaseName)
	if err != nil {
		if errors.Is(err, driver.ErrReleaseNotFound) {
			exists = false
		} else {
			// it doesnt exist
			r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
		}
	}
	log.Debugf("Release %s exists=%v", releaseName, exists)
	clientSet, err := utils.GetClientKubeWithConf(r.Config)
	if err != nil {
		r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
	}
	svc, err := createPeerService(
		clientSet,
		chartName,
		fabricPeer,
	)
	if err != nil {
		r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
		return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
	}
	reqLogger.Info(fmt.Sprintf("Service %s created", svc.Name))
	if exists {
		// update
		c, err := GetConfig(fabricPeer, clientSet, releaseName, req.Namespace, svc, false)
		if err != nil {
			r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
		}

		err = r.upgradeChart(cfg, err, ns, releaseName, c)
		if err != nil {
			r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
		}
		lastTimeCertsRenewed := fabricPeer.Status.LastCertificateUpdate
		if fabricPeer.Status.LastCertificateUpdate != nil {
			if fabricPeer.Status.LastCertificateUpdate != nil {
				lastCertificateUpdate := fabricPeer.Status.LastCertificateUpdate.Time
				if fabricPeer.Spec.UpdateCertificateTime.Time.After(lastCertificateUpdate) {
					// must update the certificates and block until it's done
					// scale down to zero replicas
					// wait for the deployment to scale down
					// update the certs
					// scale up the peer
					log.Infof("Trying to upgrade certs")
					err := r.updateCerts(req, fabricPeer, clientSet, releaseName, svc, ctx, cfg, ns)
					if err != nil {
						log.Errorf("Error renewing certs: %v", err)
						r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
						return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
					}
					lastTimeCertsRenewed = fabricPeer.Spec.UpdateCertificateTime
				}
			}
		} else if fabricPeer.Status.LastCertificateUpdate == nil && fabricPeer.Spec.UpdateCertificateTime != nil {
			log.Infof("Trying to upgrade certs")
			err := r.updateCerts(req, fabricPeer, clientSet, releaseName, svc, ctx, cfg, ns)
			if err != nil {
				log.Errorf("Error renewing certs: %v", err)
				r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
				return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
			}
			lastTimeCertsRenewed = fabricPeer.Spec.UpdateCertificateTime
		}
		s, err := GetPeerState(cfg, r.Config, releaseName, ns, svc)
		if err != nil {
			r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
		}

		fPeer := fabricPeer.DeepCopy()
		fPeer.Status.Status = s.Status
		fPeer.Status.TlsCert = s.TlsCert
		fPeer.Status.TlsCACert = s.TlsCACert
		fPeer.Status.SignCert = s.SignCert
		fPeer.Status.SignCACert = s.SignCACert
		fPeer.Status.NodePort = s.NodePort
		fPeer.Status.LastCertificateUpdate = lastTimeCertsRenewed
		fPeer.Status.Conditions.SetCondition(status.Condition{
			Type:   status.ConditionType(s.Status),
			Status: "True",
		})
		if !reflect.DeepEqual(fPeer.Status, fabricPeer.Status) {
			if err := r.Status().Update(ctx, fPeer); err != nil {
				log.Errorf("Error updating the status: %v", err)
				r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
				return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
			}
		}
		log.Infof("Peer %s in %s status", fPeer.Name, string(s.Status))
		switch s.Status {
		case hlfv1alpha1.PendingStatus:
			log.Infof("Peer %s in %s status", fPeer.Name, string(s.Status))
			return ctrl.Result{
				RequeueAfter: 10 * time.Second,
			}, nil
		case hlfv1alpha1.FailedStatus:
			log.Infof("Peer %s in %s status", fPeer.Name, string(s.Status))
			return ctrl.Result{
				RequeueAfter: 10 * time.Second,
			}, nil
		case hlfv1alpha1.RunningStatus:
			return ctrl.Result{}, nil
		default:
			return ctrl.Result{
				RequeueAfter: 2 * time.Second,
			}, nil
		}
	} else {
		cmd := action.NewInstall(cfg)
		name, chart, err := cmd.NameAndChart([]string{releaseName, r.ChartPath})
		if err != nil {
			r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
		}

		cmd.ReleaseName = name
		ch, err := loader.Load(chart)
		if err != nil {
			r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
		}
		c, err := GetConfig(
			fabricPeer,
			clientSet,
			name,
			req.Namespace,
			svc,
			false,
		)
		if err != nil {
			r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
		}
		var inInterface map[string]interface{}
		inrec, err := json.Marshal(c)
		if err != nil {
			r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
		}
		err = json.Unmarshal(inrec, &inInterface)
		if err != nil {
			r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
		}
		release, err := cmd.Run(ch, inInterface)
		if err != nil {
			reqLogger.Error(err, "Failed to install chart")
			r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
		}
		log.Infof("Chart installed %s", release.Name)
		fabricPeer.Status.Status = hlfv1alpha1.PendingStatus
		fabricPeer.Status.Conditions.SetCondition(status.Condition{
			Type:               "DEPLOYED",
			Status:             "True",
			LastTransitionTime: v1.Time{},
		})
		if err := r.Status().Update(ctx, fabricPeer); err != nil {
			r.setConditionStatus(ctx, fabricPeer, hlfv1alpha1.FailedStatus, false, err, false)
			return r.updateCRStatusOrFailReconcile(ctx, r.Log, fabricPeer)
		}
		return ctrl.Result{
			Requeue:      false,
			RequeueAfter: 10 * time.Second,
		}, nil
	}
}

func (r *FabricPeerReconciler) updateCerts(req ctrl.Request, fPeer *hlfv1alpha1.FabricPeer, clientSet *kubernetes.Clientset, releaseName string, svc *corev1.Service, ctx context.Context, cfg *action.Configuration, ns string) error {
	log.Infof("Trying to upgrade certs")
	r.setConditionStatus(ctx, fPeer, hlfv1alpha1.UpdatingCertificates, false, nil, false)
	config, err := GetConfig(fPeer, clientSet, releaseName, req.Namespace, svc, true)
	if err != nil {
		log.Errorf("Error getting the config: %v", err)
		return err
	}
	//config.Replicas = 0
	err = r.upgradeChart(cfg, err, ns, releaseName, config)
	if err != nil {
		return err
	}
	dep, err := GetPeerDeployment(
		cfg,
		r.Config,
		releaseName,
		req.Namespace,
	)
	if err != nil {
		return err
	}
	err = restartDeployment(
		r.Config,
		dep,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *FabricPeerReconciler) upgradeChart(
	cfg *action.Configuration,
	err error,
	ns string,
	releaseName string,
	c *FabricPeerChart,
) error {
	inrec, err := json.Marshal(c)
	if err != nil {
		return err
	}
	var inInterface map[string]interface{}
	err = json.Unmarshal(inrec, &inInterface)
	if err != nil {
		return err
	}
	cmd := action.NewUpgrade(cfg)
	cmd.MaxHistory = 5
	err = os.Setenv("HELM_NAMESPACE", ns)
	if err != nil {
		return err
	}
	settings := cli.New()
	chartPath, err := cmd.LocateChart(r.ChartPath, settings)
	ch, err := loader.Load(chartPath)
	if err != nil {
		return err
	}
	cmd.Wait = true
	release, err := cmd.Run(releaseName, ch, inInterface)
	if err != nil {
		return err
	}
	log.Infof("Chart upgraded %s", release.Name)
	return nil
}

func (r *FabricPeerReconciler) setConditionStatus(ctx context.Context, p *hlfv1alpha1.FabricPeer, conditionType hlfv1alpha1.DeploymentStatus, statusFlag bool, err error, statusUnknown bool) (update bool) {
	statusStr := func() corev1.ConditionStatus {
		if statusUnknown {
			return corev1.ConditionUnknown
		}
		if statusFlag {
			return corev1.ConditionTrue
		} else {
			return corev1.ConditionFalse
		}
	}
	if p.Status.Status != conditionType {
		depCopy := client.MergeFrom(p.DeepCopy())
		p.Status.Status = conditionType
		err = r.Status().Patch(ctx, p, depCopy)
		if err != nil {
			log.Warnf("Failed to update status to %s: %v", conditionType, err)
		}
	}
	if err != nil {
		p.Status.Message = err.Error()
	}
	condition := func() status.Condition {
		if err != nil {
			return status.Condition{
				Type:    status.ConditionType(conditionType),
				Status:  statusStr(),
				Reason:  status.ConditionReason(err.Error()),
				Message: err.Error(),
			}
		}
		return status.Condition{
			Type:   status.ConditionType(conditionType),
			Status: statusStr(),
		}
	}
	return p.Status.Conditions.SetCondition(condition())
}

func getExistingTLSOPSCrypto(client *kubernetes.Clientset, chartName string, namespace string) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	secretName := fmt.Sprintf("%s-tls-ops", chartName)
	tlsRootSecretName := fmt.Sprintf("%s-tlsrootcert", chartName)
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

var (
	ErrClientK8s = errors.New("k8sAPIClientError")
)

func (r *FabricPeerReconciler) updateCRStatusOrFailReconcile(ctx context.Context, log logr.Logger, p *hlfv1alpha1.FabricPeer) (
	reconcile.Result, error) {
	if err := r.Status().Update(ctx, p); err != nil {
		log.Error(err, fmt.Sprintf("%v failed to update the application status", ErrClientK8s))
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func getExistingTLSCrypto(client *kubernetes.Clientset, chartName string, namespace string) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	secretName := fmt.Sprintf("%s-tls", chartName)
	tlsRootSecretName := fmt.Sprintf("%s-tlsrootcert", chartName)
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

func getExistingSignCrypto(client *kubernetes.Clientset, chartName string, namespace string) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	secretCrtName := fmt.Sprintf("%s-idcert", chartName)
	secretKeyName := fmt.Sprintf("%s-idkey", chartName)
	secretRootCrtName := fmt.Sprintf("%s-cacert", chartName)

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

func CreateTLSCryptoMaterial(conf *hlfv1alpha1.FabricPeer, caName string, caurl string, enrollID string, enrollSecret string, tlsCertString string, hosts []string) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	tlsCert, tlsKey, tlsRootCert, err := certs.EnrollUser(certs.EnrollUserRequest{
		TLSCert:    tlsCertString,
		URL:        caurl,
		Name:       caName,
		MSPID:      conf.Spec.MspID,
		User:       enrollID,
		Secret:     enrollSecret,
		Hosts:      hosts,
		CN:         "",
		Profile:    "tls",
		Attributes: nil,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return tlsCert, tlsKey, tlsRootCert, nil
}

func CreateTLSOPSCryptoMaterial(conf *hlfv1alpha1.FabricPeer, caName string, caurl string, enrollID string, enrollSecret string, tlsCertString string, hosts []string) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	tlsCert, tlsKey, tlsRootCert, err := certs.EnrollUser(
		certs.EnrollUserRequest{
			TLSCert:    tlsCertString,
			URL:        caurl,
			Name:       caName,
			MSPID:      conf.Spec.MspID,
			User:       enrollID,
			Secret:     enrollSecret,
			Hosts:      hosts,
			CN:         "",
			Profile:    "tls",
			Attributes: nil,
		},
	)
	if err != nil {
		return nil, nil, nil, err
	}
	return tlsCert, tlsKey, tlsRootCert, nil
}

func CreateSignCryptoMaterial(conf *hlfv1alpha1.FabricPeer, caName string, caurl string, enrollID string, enrollSecret string, tlsCertString string) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, error) {
	tlsCert, tlsKey, tlsRootCert, err := certs.EnrollUser(certs.EnrollUserRequest{
		TLSCert: tlsCertString,
		URL:     caurl,
		Name:    caName,
		MSPID:   conf.Spec.MspID,
		User:    enrollID,
		Secret:  enrollSecret,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return tlsCert, tlsKey, tlsRootCert, nil
}

func GetConfig(
	conf *hlfv1alpha1.FabricPeer,
	client *kubernetes.Clientset,
	chartName string,
	namespace string,
	svc *corev1.Service,
	refreshCerts bool,
) (*FabricPeerChart, error) {
	spec := conf.Spec
	tlsParams := conf.Spec.Secret.Enrollment.TLS
	tlsCAUrl := fmt.Sprintf("https://%s:%d", tlsParams.Cahost, tlsParams.Caport)
	ingressHosts := spec.Hosts
	var hosts []string
	hosts = append(hosts, tlsParams.Csr.Hosts...)
	hosts = append(hosts, ingressHosts...)
	var tlsCert, tlsRootCert, tlsOpsCert, signCert, signRootCert *x509.Certificate
	var tlsKey, tlsOpsKey, signKey *ecdsa.PrivateKey
	var err error
	if refreshCerts {
		cacert, err := base64.StdEncoding.DecodeString(tlsParams.Catls.Cacert)
		if err != nil {
			return nil, err
		}
		tlsCert, tlsKey, tlsRootCert, err = CreateTLSCryptoMaterial(
			conf,
			tlsParams.Caname,
			tlsCAUrl,
			tlsParams.Enrollid,
			tlsParams.Enrollsecret,
			string(cacert),
			hosts,
		)
		if err != nil {
			return nil, err
		}
	} else {
		tlsCert, tlsKey, tlsRootCert, err = getExistingTLSCrypto(client, chartName, namespace)
		if err != nil {
			cacert, err := base64.StdEncoding.DecodeString(tlsParams.Catls.Cacert)
			if err != nil {
				return nil, err
			}
			tlsCert, tlsKey, tlsRootCert, err = CreateTLSCryptoMaterial(
				conf,
				tlsParams.Caname,
				tlsCAUrl,
				tlsParams.Enrollid,
				tlsParams.Enrollsecret,
				string(cacert),
				hosts,
			)
			if err != nil {
				return nil, err
			}
		}
	}
	if refreshCerts {
		cacert, err := base64.StdEncoding.DecodeString(tlsParams.Catls.Cacert)
		if err != nil {
			return nil, err
		}
		tlsOpsCert, tlsOpsKey, _, err = CreateTLSOPSCryptoMaterial(
			conf,
			tlsParams.Caname,
			tlsCAUrl,
			tlsParams.Enrollid,
			tlsParams.Enrollsecret,
			string(cacert),
			hosts,
		)
		if err != nil {
			return nil, err
		}
	} else {
		tlsOpsCert, tlsOpsKey, _, err = getExistingTLSOPSCrypto(client, chartName, namespace)
		if err != nil {
			cacert, err := base64.StdEncoding.DecodeString(tlsParams.Catls.Cacert)
			if err != nil {
				return nil, err
			}
			tlsOpsCert, tlsOpsKey, _, err = CreateTLSOPSCryptoMaterial(
				conf,
				tlsParams.Caname,
				tlsCAUrl,
				tlsParams.Enrollid,
				tlsParams.Enrollsecret,
				string(cacert),
				hosts,
			)
			if err != nil {
				return nil, err
			}
		}
	}
	signParams := conf.Spec.Secret.Enrollment.Component
	caUrl := fmt.Sprintf("https://%s:%d", signParams.Cahost, signParams.Caport)
	if refreshCerts {
		cacert, err := base64.StdEncoding.DecodeString(signParams.Catls.Cacert)
		if err != nil {
			return nil, err
		}
		signCert, signKey, signRootCert, err = CreateSignCryptoMaterial(
			conf,
			signParams.Caname,
			caUrl,
			signParams.Enrollid,
			signParams.Enrollsecret,
			string(cacert),
		)
		if err != nil {
			return nil, err
		}
	} else {
		signCert, signKey, signRootCert, err = getExistingSignCrypto(client, chartName, namespace)
		if err != nil {
			cacert, err := base64.StdEncoding.DecodeString(signParams.Catls.Cacert)
			if err != nil {
				return nil, err
			}
			signCert, signKey, signRootCert, err = CreateSignCryptoMaterial(
				conf,
				signParams.Caname,
				caUrl,
				signParams.Enrollid,
				signParams.Enrollsecret,
				string(cacert),
			)
			if err != nil {
				return nil, err
			}
		}
	}
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
	tlsOpsCRTEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: tlsOpsCert.Raw,
	})
	tlsOpsEncodedPK, err := x509.MarshalPKCS8PrivateKey(tlsOpsKey)
	if err != nil {
		return nil, err
	}
	tlsOpsPEMEncodedPK := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: tlsOpsEncodedPK,
	})

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
	var externalEndpoint string
	if spec.ExternalEndpoint != "" {
		externalEndpoint = spec.ExternalEndpoint
	} else {
		requestNodePort, err := getRequestNodePort(svc)
		if err != nil {
			return nil, err
		}
		publicIP, err := utils.GetPublicIPKubernetes(client)
		if err != nil {
			return nil, err
		}
		externalEndpoint = fmt.Sprintf("%s:%d", publicIP, requestNodePort)
	}

	gossipExternalEndpoint := spec.Gossip.ExternalEndpoint
	if gossipExternalEndpoint == "" {
		gossipExternalEndpoint = externalEndpoint
	}
	gossipEndpoint := spec.Gossip.Endpoint
	if gossipEndpoint == "" {
		gossipEndpoint = externalEndpoint
	}
	externalBuilders := []ExternalBuilder{}
	for _, builder := range spec.ExternalBuilders {
		externalBuilders = append(externalBuilders, ExternalBuilder{
			Name:                 builder.Name,
			Path:                 builder.Path,
			PropagateEnvironment: builder.PropagateEnvironment,
		})
	}
	imagePullPolicy := spec.ImagePullPolicy
	if imagePullPolicy == "" {
		imagePullPolicy = hlfv1alpha1.DefaultImagePullPolicy
	}
	var hostAliases []HostAlias
	for _, hostAlias := range spec.HostAliases {
		hostAliases = append(hostAliases, HostAlias{
			IP:        hostAlias.IP,
			Hostnames: hostAlias.Hostnames,
		})
	}
	stateDb := "goleveldb"
	switch spec.StateDb {
	case hlfv1alpha1.StateDBCouchDB:
		stateDb = "CouchDB"
	case hlfv1alpha1.StateDBLevelDB:
		stateDb = "goleveldb"
	default:
		stateDb = "goleveldb"
	}
	var monitor ServiceMonitor
	if spec.ServiceMonitor != nil && spec.ServiceMonitor.Enabled {
		monitor = ServiceMonitor{
			Enabled:           spec.ServiceMonitor.Enabled,
			Labels:            spec.ServiceMonitor.Labels,
			Interval:          spec.ServiceMonitor.Interval,
			ScrapeTimeout:     spec.ServiceMonitor.ScrapeTimeout,
			Scheme:            "http",
			Relabelings:       []interface{}{},
			TargetLabels:      []interface{}{},
			MetricRelabelings: []interface{}{},
			SampleLimit:       spec.ServiceMonitor.SampleLimit,
		}
	} else {
		monitor = ServiceMonitor{Enabled: false}
	}
	var istio Istio
	if spec.Istio != nil {
		gateway := spec.Istio.IngressGateway
		if gateway == "" {
			gateway = "ingressgateway"
		}
		istio = Istio{
			Port:           spec.Istio.Port,
			Hosts:          spec.Istio.Hosts,
			IngressGateway: gateway,
		}
	} else {
		istio = Istio{
			Port:           0,
			Hosts:          []string{},
			IngressGateway: "",
		}
	}
	var c = FabricPeerChart{
		Replicas: spec.Replicas,
		Istio:    istio,
		Image: Image{
			Repository: spec.Image,
			Tag:        spec.Tag,
			PullPolicy: string(imagePullPolicy),
		},
		ServiceMonitor:   monitor,
		ExternalBuilders: externalBuilders,
		DockerSocketPath: spec.DockerSocketPath,
		Peer: Peer{
			DatabaseType: stateDb,
			MspID:        spec.MspID,
			Gossip: Gossip{
				Bootstrap:         spec.Gossip.Bootstrap,
				Endpoint:          gossipEndpoint,
				ExternalEndpoint:  gossipExternalEndpoint,
				OrgLeader:         spec.Gossip.OrgLeader,
				UseLeaderElection: spec.Gossip.UseLeaderElection,
			},
			TLS: TLSAuth{
				Server: Server{Enabled: true},
				Client: Client{Enabled: false},
			},
		},
		ExternalChaincodeBuilder: conf.Spec.ExternalChaincodeBuilder,
		CouchdbPassword:          conf.Spec.CouchDB.User,
		CouchdbUsername:          conf.Spec.CouchDB.Password,
		Rbac:                     RBAC{Ns: namespace},
		Cert:                     string(signCRTEncoded),
		Key:                      string(signPEMEncodedPK),
		Hosts:                    ingressHosts,
		TLS: TLS{
			Cert: string(tlsCRTEncoded),
			Key:  string(tlsPEMEncodedPK),
		},
		OPSTLS: TLS{
			Cert: string(tlsOpsCRTEncoded),
			Key:  string(tlsOpsPEMEncodedPK),
		},
		Cacert:      string(signRootCRTEncoded),
		IntCacert:   ``,
		Tlsrootcert: string(tlsRootCRTEncoded),
		Resources: PeerResources{
			Peer: Resources{
				Requests: Requests{
					CPU:    spec.Resources.Peer.Requests.Cpu().String(),
					Memory: spec.Resources.Peer.Requests.Memory().String(),
				},
				Limits: Limits{
					CPU:    spec.Resources.Peer.Limits.Cpu().String(),
					Memory: spec.Resources.Peer.Limits.Memory().String(),
				},
			},
			CouchDB: Resources{
				Requests: Requests{
					CPU:    spec.Resources.CouchDB.Requests.Cpu().String(),
					Memory: spec.Resources.CouchDB.Requests.Memory().String(),
				},
				Limits: Limits{
					CPU:    spec.Resources.CouchDB.Limits.Cpu().String(),
					Memory: spec.Resources.CouchDB.Limits.Memory().String(),
				},
			},
			Chaincode: Resources{
				Requests: Requests{
					CPU:    spec.Resources.Chaincode.Requests.Cpu().String(),
					Memory: spec.Resources.Chaincode.Requests.Memory().String(),
				},
				Limits: Limits{
					CPU:    spec.Resources.Chaincode.Limits.Cpu().String(),
					Memory: spec.Resources.Chaincode.Limits.Memory().String(),
				},
			},
		},
		NodeSelector:     NodeSelector{},
		Tolerations:      nil,
		Affinity:         Affinity{},
		ExternalHost:     externalEndpoint,
		FullnameOverride: conf.Name,
		HostAliases:      hostAliases,
		Service: Service{
			Type: string(spec.Service.Type),
		},
		Persistence: PeerPersistence{
			Peer: Persistence{
				Enabled:      true,
				Annotations:  Annotations{},
				StorageClass: spec.Storage.Peer.StorageClass,
				AccessMode:   string(spec.Storage.Peer.AccessMode),
				Size:         spec.Storage.Peer.Size,
			},
			CouchDB: Persistence{
				Enabled:      true,
				Annotations:  Annotations{},
				StorageClass: spec.Storage.CouchDB.StorageClass,
				AccessMode:   string(spec.Storage.CouchDB.AccessMode),
				Size:         spec.Storage.CouchDB.Size,
			},
			Chaincode: Persistence{
				Enabled:      true,
				Annotations:  Annotations{},
				StorageClass: spec.Storage.Chaincode.StorageClass,
				AccessMode:   string(spec.Storage.Chaincode.AccessMode),
				Size:         spec.Storage.Chaincode.Size,
			},
		},
		Logging: Logging{
			Level:    conf.Spec.Logging.Level,
			Peer:     conf.Spec.Logging.Peer,
			Cauthdsl: conf.Spec.Logging.Cauthdsl,
			Gossip:   conf.Spec.Logging.Gossip,
			Grpc:     conf.Spec.Logging.Grpc,
			Ledger:   conf.Spec.Logging.Ledger,
			Msp:      conf.Spec.Logging.Msp,
			Policies: conf.Spec.Logging.Policies,
		},
	}
	return &c, nil
}

func (r *FabricPeerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hlfv1alpha1.FabricPeer{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}
func getServiceName(peer *hlfv1alpha1.FabricPeer) string {
	return peer.Name
}
func (r *FabricPeerReconciler) finalizePeer(reqLogger logr.Logger, peer *hlfv1alpha1.FabricPeer) error {
	ns := peer.Namespace
	if ns == "" {
		ns = "default"
	}
	svcName := getServiceName(peer)
	clientSet, err := utils.GetClientKubeWithConf(r.Config)
	if err != nil {
		return err
	}
	ctx := context.Background()
	err = clientSet.CoreV1().Services(ns).Delete(ctx, svcName, v1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info(fmt.Sprintf("Service %s couldn't be found", svcName))
		} else {
			reqLogger.Info(fmt.Sprintf("Service %s couldn't be deleted: %v", svcName, err))
		}
	}
	cfg, err := newActionCfg(r.Log, r.Config, ns)
	if err != nil {
		return err
	}
	releaseName := peer.Name
	reqLogger.Info("Successfully finalized peer")
	cmd := action.NewUninstall(cfg)
	resp, err := cmd.Run(releaseName)
	if err != nil {
		if strings.Compare("Release not loaded", err.Error()) != 0 {
			return nil
		}
		log.Errorf("Failed to uninstall release %s %v", releaseName, err)
		return err
	}
	log.Infof("Release %s deleted=%s", releaseName, resp.Info)
	return nil
}

const PeerPortName = "peer"
const ChaincodePortName = "chaincode"
const EventPortName = "event"
const OperationsPortName = "operations"

func getRequestNodePort(svc *corev1.Service) (int, error) {
	for _, port := range svc.Spec.Ports {
		if port.Name == PeerPortName {
			return int(port.NodePort), nil
		}
	}
	return 0, errors.Errorf("")
}
func getReleaseName(peer *hlfv1alpha1.FabricPeer) string {
	return peer.Name
}
func getNamespace(peer *hlfv1alpha1.FabricPeer) string {
	ns := peer.Namespace
	if ns == "" {
		ns = "default"
	}
	return ns
}
func createPeerService(
	clientSet *kubernetes.Clientset,
	chartName string,
	peer *hlfv1alpha1.FabricPeer,
) (*apiv1.Service, error) {
	releaseName := getReleaseName(peer)
	ns := getNamespace(peer)
	ctx := context.Background()
	svcName := releaseName
	svc, err := clientSet.CoreV1().Services(ns).Get(
		ctx,
		svcName,
		v1.GetOptions{},
	)
	exists := true
	if err != nil {
		if apierrors.IsNotFound(err) {
			exists = false
		} else {
			return nil, err
		}
	}
	if exists {
		return svc, nil
	}
	labels := map[string]string{
		"app":     chartName,
		"release": releaseName,
	}
	svc = &apiv1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name:      svcName,
			Namespace: ns,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Type: peer.Spec.Service.Type,
			Ports: []corev1.ServicePort{
				{
					Name:     PeerPortName,
					Protocol: "TCP",
					Port:     7051,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 7051,
					},
				},
				{
					Name:     ChaincodePortName,
					Protocol: "TCP",
					Port:     7052,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 7052,
					},
				},
				{
					Name:     EventPortName,
					Protocol: "TCP",
					Port:     7053,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 7053,
					},
				},
				{
					Name:     OperationsPortName,
					Protocol: "TCP",
					Port:     9443,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 9443,
					},
				},
			},
			Selector: labels,
		},
		Status: corev1.ServiceStatus{},
	}
	return clientSet.CoreV1().Services(ns).Create(ctx, svc, v1.CreateOptions{})
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
