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

package main

import (
	"flag"
	"github.com/kfsoftware/hlf-operator/controllers/hlfmetrics"
	"github.com/kfsoftware/hlf-operator/controllers/ordnode"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
	"os"
	"path/filepath"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/kfsoftware/hlf-operator/controllers/ca"
	"github.com/kfsoftware/hlf-operator/controllers/ordservice"
	"github.com/kfsoftware/hlf-operator/controllers/peer"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	hlfv1alpha1 "github.com/kfsoftware/hlf-operator/api/hlf.kungfusoftware.es/v1alpha1"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(hlfv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-addr", ":8090", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	kubeContext, exists := os.LookupEnv("KUBECONTEXT")
	var restConfig *rest.Config
	var err error
	if exists {
		restConfig, err = config.GetConfigWithContext(kubeContext)
		if err != nil {
			log.Fatalf("Failed to get context %s", kubeContext)
		}
	} else {
		restConfig = ctrl.GetConfigOrDie()
	}
	// Register custom metrics with the global prometheus registry
	metrics.Registry.MustRegister(hlfmetrics.CertificateExpiryTimeSeconds)
	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "a1f969eb.kungfusoftware.es",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}
	peerChartPath, err := filepath.Abs("./charts/hlf-peer")
	if err != nil {
		setupLog.Error(err, "unable to find the peer chart")
		os.Exit(1)
	}
	if err = (&peer.FabricPeerReconciler{
		Client:    mgr.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("FabricPeer"),
		Scheme:    mgr.GetScheme(),
		Config:    mgr.GetConfig(),
		ChartPath: peerChartPath,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricPeer")
		os.Exit(1)
	}
	caChartPath, err := filepath.Abs("./charts/hlf-ca")
	if err != nil {
		setupLog.Error(err, "unable to find the ca chart")
		os.Exit(1)
	}
	clientSet, err := utils.GetClientKubeWithConf(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "unable to create client set", "controller", "FabricPeer")
		os.Exit(1)
	}
	if err = (&ca.FabricCAReconciler{
		Client:    mgr.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("FabricCA"),
		Scheme:    mgr.GetScheme(),
		Config:    mgr.GetConfig(),
		ClientSet: clientSet,
		ChartPath: caChartPath,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricCA")
		os.Exit(1)
	}
	ordServiceChartPath, err := filepath.Abs("./charts/hlf-ord")
	if err != nil {
		setupLog.Error(err, "unable to find the orderer chart")
		os.Exit(1)
	}
	if err = (&ordservice.FabricOrderingServiceReconciler{
		Client:    mgr.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("FabricOrderingService"),
		Scheme:    mgr.GetScheme(),
		Config:    mgr.GetConfig(),
		ChartPath: ordServiceChartPath,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricOrderingService")
		os.Exit(1)
	}

	ordNodeChartPath, err := filepath.Abs("./charts/hlf-ordnode")
	if err != nil {
		setupLog.Error(err, "unable to find the orderer node chart")
		os.Exit(1)
	}
	if err = (&ordnode.FabricOrdererNodeReconciler{
		Client:    mgr.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("FabricOrdererNode"),
		Scheme:    mgr.GetScheme(),
		Config:    mgr.GetConfig(),
		ChartPath: ordNodeChartPath,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricOrdererNode")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder
	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
