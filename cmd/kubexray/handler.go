package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/Sirupsen/logrus"
	"gopkg.in/yaml.v2"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Handler interface contains the methods that are required
type Handler interface {
	Init(client kubernetes.Interface, config *rest.Config) error
	ObjectCreated(client kubernetes.Interface, obj interface{})
	ObjectDeleted(client kubernetes.Interface, obj interface{})
	ObjectUpdated(client kubernetes.Interface, objOld, objNew interface{})
}

// ResourceType represents the type of Kubernetes resource a pod belongs to.
type ResourceType byte

const (
	Unrecognized ResourceType = iota
	StatefulSet
	Deployment
	DaemonSet
	ReplicaSet
	ReplicationController
	Job
	CronJob
	Podonly
)

// Action represents the action taken against a problematic pod.
type Action byte

const (
	Ignore Action = iota
	Scaledown
	Delete
)

// HandlerImpl is a sample implementation of Handler
type HandlerImpl struct {
	clusterurl      string
	url             string
	user            string
	pass            string
	slackWebhook    string
	webhookToken    string
	namespaceconfig Config
}
type KubeXrayLog struct {
	namespace              string                   `json:"namespace"`
	isWhitelisted          bool                     `json:"isWhitelisted"`
	isDefaultPolicyApplied bool                     `json:"isDefaultPolicyApplied"`
	imageName              []NotifyComponentPayload `json:"imageName"`
	isRecognized           bool                     `json:"isRecognized"`
	hasSecurityIssues      bool                     `json:"hasSecurityIssues"`
	hasLicenseIssues       bool                     `json:"hasLicenseIssues"`
	actionTaken            string                   `json:"actionTaken"`
	issuesSummary          interface{}                   `json:"issuesSummary"`
}

type Config struct {
	WhitelistNamespaces []string
	Namespaces          map[string]NamespacePolicy `yaml:"namespacepolicy"`
	DefaultPolicy       NamespacePolicy
}

type NamespacePolicy struct {
	Unscanned Policy
	Security  Policy
	License   Policy
}

type Policy struct {
	Deployments  string
	Statefulsets string
	Others string
}

// NotifyComponentPayload is a component structure in NotifyPayload.
type NotifyComponentPayload struct {
	Name     string `json:"component_name"`
	Checksum string `json:"component_sha"`
}

// NotifyPayload is the payload used to notify xray of changes.
type NotifyPayload struct {
	Name       string                   `json:"pod_name"`
	Namespace  string                   `json:"namespace"`
	Action     string                   `json:"action"`
	Cluster    string                   `json:"cluster_url"`
	Components []NotifyComponentPayload `json:"components"`
}

// Init initializes the handler with configuration data.
func (t *HandlerImpl) Init(client kubernetes.Interface, config *rest.Config) error {
	log.Debug("HandlerImpl.Init")
	host := config.Host
	if host[len(host)-1] != '/' {
		host += "/"
	}
	t.clusterurl = host
	url, user, pass, slack, token, err := getXrayConfig("/config/secret/xray_config.yaml", "./xray_config.yaml")
	if err != nil {
		log.Error("Cannot read xray_config.yaml: ", err)
		return err
	}
	t.url = url
	t.user = user
	t.pass = pass
	t.slackWebhook = slack
	t.webhookToken = token
	namespaceconfig, err := getConfig("/config/conf/config.yaml", "./config.yaml")
	if err != nil {
		log.Warn("Cannot read config.yaml: ", err)
	}
	if t.webhookToken != "" {
		setupXrayWebhook(t, client)
	}
	t.namespaceconfig = namespaceconfig
	log.Debug("Namespace list ", namespaceconfig)
	return nil

}

// temporary structure for search results in webhook code
type searchItem struct {
	severity string
	isstype  string
	sha2     string
	name     string
	action   string
	pod      *core_v1.Pod
}

// parses the xray webhook request body
func parseWebhook(body interface{}) []searchItem {
	result := make([]searchItem, 0)
	bodymap := body.(map[string]interface{})
	for _, iss := range bodymap["issues"].([]interface{}) {
		issue := iss.(map[string]interface{})
		severity := issue["severity"].(string)
		isstype := issue["type"].(string)
		if (severity != "Major" && severity != "Critical" && severity != "High") || isstype == "" {
			continue
		}
		if _, ok := issue["impacted_artifacts"]; !ok {
			log.Debugf("Unable to process webhook, xray did not include impacted component data. Payload: %v", body)
			continue
		}


		for _, art := range issue["impacted_artifacts"].([]interface{}) {
			artif := art.(map[string]interface{})
			pkgtype := artif["pkg_type"].(string)
			sha2 := artif["sha256"].(string)
			if pkgtype != "Docker" || sha2 == "" {
				continue
			}
			res := searchItem{severity, isstype, sha2, "", "", nil}
			result = append(result, res)
		}
	}
	return result
}

// searches for checksums provided by the xray webhook, returning those that
// match active running containers
func searchChecksums(client kubernetes.Interface, shas []searchItem) ([]searchItem, error) {
	result := make([]searchItem, 0)
	nss, err := client.CoreV1().Namespaces().List(meta_v1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, ns := range nss.Items {
		pods, err := client.CoreV1().Pods(ns.Name).List(meta_v1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, pod := range pods.Items {
			for _, stat := range pod.Status.ContainerStatuses {
				idx := strings.LastIndex(stat.ImageID, "sha256:")
				if idx == -1 {
					continue
				}
				sha2 := stat.ImageID[idx+7:]
				for _, item := range shas {
					if item.sha2 == sha2 {
						res := item
						res.name = stat.Image
						res.pod = &pod
						result = append(result, res)
					}
				}
			}
		}
	}
	return result, nil
}

// setup the webhook for xray to call
func setupXrayWebhook(t *HandlerImpl, client kubernetes.Interface) {
	go func() {
		http.HandleFunc("/", handleXrayWebhook(t, client))
		err := http.ListenAndServe(":8765", nil)
		if err != nil {
			log.Errorf("Error running Xray webhook: %v", err)
		}
	}()
}

// handle when xray calls the webhook
func handleXrayWebhook(t *HandlerImpl, client kubernetes.Interface) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		log.Debug("Webhook triggered by Xray")
		// check the auth token and fail if it's wrong
		toks := req.Header["X-Auth-Token"]
		if len(toks) <= 0 || toks[0] != t.webhookToken {
			log.Warn("Xray did not send an appropriate token, aborting webhook")
			resp.WriteHeader(403)
			return
		}
		// parse the webhook request payload
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			log.Errorf("Error reading webhook request: %v", err)
			resp.WriteHeader(400)
			return
		}
		var data interface{}
		err = json.Unmarshal(body, &data)
		if err != nil {
			log.Errorf("Error reading webhook request: %v", err)
			resp.WriteHeader(400)
			return
		}
		// find matching checksums in the cluster
		searchterms := parseWebhook(data)
		searchresult, err := searchChecksums(client, searchterms)
		if err != nil {
			log.Errorf("Error handling webhook request: %v", err)
			resp.WriteHeader(500)
			return
		}
		// check each match against the config to decide how to deal with it
		for _, term := range searchresult {
			_, typ := checkResource(client, term.pod)

			if isWhitelistedNamespace(t, term.pod) {
				log.Debug("Ignoring pod: %s (due to whitelisted namespace: %s)", term.pod.Name, term.pod.Namespace)
				//KubeXrayLoging(pod.Namespace, iswhitelist, defaultpolicy, comps, rec, seciss, liciss, "Ignoring POD in whitelistnamespaces", "whitelistnamespaces")
				continue
			}

			var namespacePolicy = t.namespaceconfig.Namespaces[term.pod.Namespace]

			var podpolicy = term.pod.Namespace

			_, ok := t.namespaceconfig.Namespaces[podpolicy]

			if !ok {
				namespacePolicy = t.namespaceconfig.DefaultPolicy
			}

			delete, scaledown := false, false
			if typ == Deployment {
				if term.isstype == "security" {
					if namespacePolicy.Security.Deployments == "Delete" {
						delete = true
					} else if namespacePolicy.Security.Deployments == "Scaledown" {
						scaledown = true
					}
				} else if term.isstype == "license" {
					if namespacePolicy.Security.Deployments == "Delete" {
						delete = true
					} else if namespacePolicy.License.Deployments == "Scaledown" {
						scaledown = true
					}
				}
			} else if typ == StatefulSet {
				if term.isstype == "security" {
					if namespacePolicy.Security.Statefulsets == "Delete" {
						delete = true
					} else if namespacePolicy.Security.Statefulsets == "Scaledown" {
						scaledown = true
					}
				} else if term.isstype == "license" {
					if namespacePolicy.License.Statefulsets == "Delete" {
						delete = true
					} else if namespacePolicy.License.Statefulsets == "Scaledown" {
						scaledown = true
					}
				}
			}
			if delete || scaledown {
				// remove the pod by either deleting it or scaling it to zero replicas
				if delete {
					term.action = "delete"
				} else {
					term.action = "scaledown"
				}
				removePod(client, term.pod, typ, delete)
			} else {
				log.Debugf("Ignoring pod: %s", term.pod.Name)
			}
		}
		// send notification to xray
		groups := make(map[types.UID][]*searchItem)
		for _, item := range searchresult {
			if item.action == "" {
				continue
			}
			group, ok := groups[item.pod.UID]
			if !ok {
				group = make([]*searchItem, 0)
			}
			groups[item.pod.UID] = append(group, &item)
		}
		for _, group := range groups {
			comp := make([]NotifyComponentPayload, 0)
			act := "scaledown"
			for _, item := range group {
				c := NotifyComponentPayload{Name: item.name, Checksum: item.sha2}
				if item.action == "delete" {
					act = "delete"
				}
				comp = append(comp, c)
			}
			payload := NotifyPayload{Name: group[0].pod.Name, Namespace: group[0].pod.Namespace, Action: act, Cluster: t.clusterurl, Components: comp}
			// send a slack notification if applicable

			if t.slackWebhook != "" {
				notifyForPod(t.slackWebhook, payload, group[0].isstype == "security", group[0].isstype == "license")
			}
			err := sendXrayNotify(t, payload)
			if err != nil {
				log.Errorf("Problem notifying xray about pod %s: %s", payload.Name, err)
			}
		}
		resp.WriteHeader(200)
	}
}

// ObjectCreated is called when an object is created
func (t *HandlerImpl) ObjectCreated(client kubernetes.Interface, obj interface{}) {
	pod := obj.(*core_v1.Pod)
	defaultpolicy := false
	iswhitelist := false
	log.Debug("HandlerImpl.ObjectCreated")
	_, typ := checkResource(client, pod)
	comps, rec, seciss, liciss, resp := getPodInfo(t, pod)
	if isWhitelistedNamespace(t, pod) {
		log.Debug("Ignoring pod: %s (due to whitelisted namespace: %s)", pod.Name, pod.Namespace)
		iswhitelist = true
		KubeXrayLoging(pod.Namespace, iswhitelist, defaultpolicy, comps, rec, seciss, liciss, "Ignoring POD in whitelistnamespaces", resp)
		return
	}

	var namespacePolicy = t.namespaceconfig.Namespaces[pod.Namespace]

	var podpolicy = pod.Namespace

	_, ok := t.namespaceconfig.Namespaces[podpolicy]

	if !ok {
		namespacePolicy = t.namespaceconfig.DefaultPolicy
		defaultpolicy = true
	}

	delete, scaledown := false, false
	check := func(pol Policy) {
		if typ == Deployment && pol.Deployments == "delete" {
			delete = true
		} else if typ == Deployment && pol.Deployments == "scaledown" {
			scaledown = true
		} else if typ == StatefulSet && pol.Statefulsets == "delete" {
			delete = true
		} else if typ == StatefulSet && pol.Statefulsets == "scaledown" {
			scaledown = true
		} else if typ == DaemonSet && pol.Others == "delete" {
		delete = true
	} else if typ == ReplicaSet && pol.Others == "delete" {
			delete = true
		} else if typ == ReplicationController && pol.Others == "delete" {
			delete = true
		} else if typ == Job && pol.Others == "delete" {
			delete = true
		} else if typ == CronJob && pol.Others == "delete" {
			delete = true
		} else if typ == Podonly && pol.Others == "delete" {
			delete = true
		}
	}
	if !rec {
		check(namespacePolicy.Unscanned)
	}
	if seciss {
		check(namespacePolicy.Security)
	}
	if liciss {
		check(namespacePolicy.License)
	}

	act := ""
	if delete {
		act = "delete"
	} else if scaledown {
		act = "scaledown"
	}

	payload := NotifyPayload{Name: pod.Name, Namespace: pod.Namespace, Action: act, Cluster: t.clusterurl, Components: comps}
	KubeXrayLoging(pod.Namespace, iswhitelist, defaultpolicy, comps, rec, seciss, liciss, act, resp)
	if t.slackWebhook != "" && (!rec || seciss || liciss) {
		notifyForPod(t.slackWebhook, payload, seciss, liciss)
	}
	if delete || scaledown {
		removePod(client, pod, typ, delete)
		err := sendXrayNotify(t, payload)
		if err != nil {
			log.Errorf("Problem notifying xray about pod %s: %s", payload.Name, err)
		}
	} else {
		log.Debugf("Ignoring pod: %s", pod.Name)
	}
}

func KubeXrayLoging(namespace string, iswhitelisted bool, isdefaultpolicyapplied bool, imagename []NotifyComponentPayload, isrecognized bool, hassecurityissues bool, haslicenseissues bool, actiontaken string, issuessummary interface{}) {

	//one pod have multiple image so using NotifyComponentPayload[] arrray so show multiple image name and sha
	kubexraylogs := KubeXrayLog{
		namespace:              namespace,
		imageName:              imagename,
		isRecognized:           isrecognized,
		hasSecurityIssues:      hassecurityissues,
		hasLicenseIssues:       haslicenseissues,
		issuesSummary:          issuessummary,
		isWhitelisted:          iswhitelisted,
		actionTaken:            actiontaken,
		isDefaultPolicyApplied: isdefaultpolicyapplied}
	log.Debugf("%+v", kubexraylogs)
	log.Infof("%+v", kubexraylogs)
}

// ObjectDeleted is called when an object is deleted
func (t *HandlerImpl) ObjectDeleted(client kubernetes.Interface, obj interface{}) {
	log.Debug("HandlerImpl.ObjectDeleted")
}

// ObjectUpdated is called when an object is updated
func (t *HandlerImpl) ObjectUpdated(client kubernetes.Interface, objOld, objNew interface{}) {
	log.Debug("HandlerImpl.ObjectUpdated")
}

// send the notification to xray
func sendXrayNotify(t *HandlerImpl, payload NotifyPayload) error {
	log.Debugf("Sending message back to xray concerning pod %s", payload.Name)
	client := &http.Client{}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	log.Debugf("Message body: %s", string(body))
	req, err := http.NewRequest("POST", t.url+"/api/v1/kube/metadata", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(t.user, t.pass)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("xray server responded with status: " + resp.Status)
	}
	return nil
}

// check if this namespace is in the whitelist for the provided violation type
func isWhitelistedNamespace(t *HandlerImpl, pod *core_v1.Pod) bool {
	whitelist := t.namespaceconfig.WhitelistNamespaces
	for _, ns := range whitelist {
		if ns == pod.Namespace {
			log.Debug("Return ns", ns)
			return true
		}
	}

	log.Debug("whitelist namespace value", whitelist)
	return false
}

// send a notification to slack
func notifyForPod(slack string, payload NotifyPayload, seciss, liciss bool) {
	log.Debugf("Sending notification concerning pod %s", payload.Name)
	if slack == "" {
		log.Warn("Unable to send notification, no Slack webhook URL configured")
		return
	}
	client := &http.Client{}
	msg1 := "*ignored*. "
	if payload.Action == "delete" {
		msg1 = "*deleted*. "
	} else if payload.Action == "scaledown" {
		msg1 = "*scaled to zero*. "
	}
	msg2 := "_Reason: Unrecognized by Xray_\n"
	if seciss {
		msg2 = "_Reason: Major security issue_\n"
	} else if liciss {
		msg2 = "_Reason: Major license issue_\n"
	}
	msg3 := "Affected components:"
	for _, comp := range payload.Components {
		msg3 += "\n• " + comp.Name + " _(sha256:" + comp.Checksum + ")_"
	}
	var js = map[string]string{
		"username": "kube-xray",
		"text":     "Pod *" + payload.Name + "* (in " + payload.Namespace + ") " + msg1 + msg2 + msg3,
	}
	encjs, err := json.Marshal(js)
	if err != nil {
		log.Warnf("Error notifying slack: %s", err)
		return
	}
	body := strings.NewReader(string(encjs))
	req, err := http.NewRequest("POST", slack, body)
	if err != nil {
		log.Warnf("Error notifying slack: %s", err)
		return
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Warnf("Error notifying slack: %s", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Warnf("Error notifying slack: response code is %s", resp.Status)
		return
	}
	log.Debug("Notification successful")
}

// get the parent resource name and type of a given pod
func checkResource(client kubernetes.Interface, pod *core_v1.Pod) (string, ResourceType) {
	subs1 := strings.LastIndexByte(pod.Name, '-')
	if subs1 < 0 {
		log.Debugf("Resource for pod %s its a pod type ", pod.Name)
		return pod.Name, Podonly
	}
	subs2 := strings.LastIndexByte(pod.Name[:subs1], '-')
	daemons := client.AppsV1().DaemonSets(pod.Namespace)
	_, err := daemons.Get(pod.Name[:subs1], meta_v1.GetOptions{})
	if err == nil {
		return pod.Name[:subs1], DaemonSet
	}
	log.Debugf("Resource for pod %s is not deamonset  %s: %v", pod.Name, pod.Name[:subs1], err)

	replicasetsobjs := client.AppsV1().ReplicaSets(pod.Namespace)
	_, err = replicasetsobjs.Get(pod.Name[:subs1], meta_v1.GetOptions{})
	if err == nil {
		return pod.Name[:subs1], ReplicaSet
	}
	log.Debugf("Resource for pod %s is not ReplicaSet  %s: %v", pod.Name, pod.Name[:subs1], err)

	replicationcontrollersobjs := client.CoreV1().ReplicationControllers(pod.Namespace)
	_, err = replicationcontrollersobjs.Get(pod.Name[:subs1], meta_v1.GetOptions{})
	if err == nil {
		return pod.Name[:subs1], ReplicationController
	}
	log.Debugf("Resource for pod %s is not ReplicationController  %s: %v", pod.Name, pod.Name[:subs1], err)

	jobsobjs := client.BatchV1().Jobs(pod.Namespace)
	_, err = jobsobjs.Get(pod.Name[:subs1], meta_v1.GetOptions{})
	if err == nil {
		return pod.Name[:subs1], ReplicationController
	}
	log.Debugf("Resource for pod %s is not jobs  %s: %v", pod.Name, pod.Name[:subs1], err)


	sets := client.AppsV1().StatefulSets(pod.Namespace)
	_, err = sets.Get(pod.Name[:subs1], meta_v1.GetOptions{})
	if err == nil {
		return pod.Name[:subs1], StatefulSet
	}
	log.Debugf("Resource for pod %s is not stateful set %s: %v", pod.Name, pod.Name[:subs1], err)
	if subs2 < 0 {
		log.Debugf("Resource for pod %s is type pod", pod.Name)
		return pod.Name, Podonly
	}
	cronjobsobjs := client.BatchV1beta1().CronJobs(pod.Namespace)
	_, err = cronjobsobjs.Get(pod.Name[:subs2], meta_v1.GetOptions{})
	if err == nil {
		return pod.Name[:subs2], CronJob
	}
	log.Debugf("Resource for pod %s is not CronJob set %s: %v", pod.Name, pod.Name[:subs2], err)

	deps := client.AppsV1().Deployments(pod.Namespace)
	_, err = deps.Get(pod.Name[:subs2], meta_v1.GetOptions{})
	if err == nil {
		return pod.Name[:subs2], Deployment
	}
	log.Debugf("Resource for pod %s its a pod type  %s: %v", pod.Name, pod.Name[:subs2], err)
	return pod.Name, Podonly
}

// remove a pod by either deleting it, or scaling it to zero replicas
func removePod(client kubernetes.Interface, pod *core_v1.Pod, typ ResourceType, delete bool) {
	deps := client.AppsV1().Deployments(pod.Namespace)
	daemonsobj := client.AppsV1().DaemonSets(pod.Namespace)
	sets := client.AppsV1().StatefulSets(pod.Namespace)
	cronjobsobj := client.BatchV1beta1().CronJobs(pod.Namespace)
	jobsobj := client.BatchV1().Jobs(pod.Namespace)
	replicationcontrollerobj := client.CoreV1().ReplicationControllers(pod.Namespace)
	replicasetsobj := client.AppsV1().ReplicaSets(pod.Namespace)
 	subs1 := strings.LastIndexByte(pod.Name, '-')
	subs2 := strings.LastIndexByte(pod.Name[:subs1], '-')
	setname := pod.Name[:subs1]
	depname := pod.Name[:subs2]
	commonname :=pod.Name[:subs1]
	if delete && typ == StatefulSet {
		log.Infof("Deleting stateful set: %s", setname)
		err := sets.Delete(setname, &meta_v1.DeleteOptions{})
		if err != nil {
			log.Warnf("Cannot delete stateful set: %s", err)
		}
	} else if delete && typ == Deployment {
		log.Infof("Deleting deployment: %s", depname)
		err := deps.Delete(depname, &meta_v1.DeleteOptions{})
		if err != nil {
			log.Warnf("Cannot delete deployment: %s", err)
		}
	} else if !delete && typ == StatefulSet {
		log.Infof("Scaling stateful set to zero pods: %s", setname)
		set, err := sets.Get(setname, meta_v1.GetOptions{})
		if err != nil {
			log.Warnf("Cannot find stateful set: %s", err)
			return
		}
		*set.Spec.Replicas = 0
		_, err = sets.Update(set)
		if err != nil {
			log.Warnf("Cannot update stateful set: %s", err)
		}
	} else if !delete && typ == Deployment {
		log.Infof("Scaling deployment to zero pods: %s", depname)
		dep, err := deps.Get(depname, meta_v1.GetOptions{})
		if err != nil {
			log.Warnf("Cannot find deployment: %s", err)
			return
		}
		*dep.Spec.Replicas = 0
		_, err = deps.Update(dep)
		if err != nil {
			log.Warnf("Cannot update deployment: %s", err)
		}
	}else if delete && typ == DaemonSet {
		log.Infof("Deleting Deamonset: %s", commonname)
		err := daemonsobj.Delete(commonname, &meta_v1.DeleteOptions{})
		if err != nil {
			log.Warnf("Cannot delete Deamonset: %s", err)
		}
	}else if delete && typ == ReplicationController {
		log.Infof("Deleting ReplicationController: %s", commonname)
		err := replicationcontrollerobj.Delete(commonname, &meta_v1.DeleteOptions{})
		if err != nil {
			log.Warnf("Cannot delete ReplicationController: %s", err)
		}
	}else if delete && typ == ReplicaSet {
		log.Infof("Deleting ReplicaSet: %s", commonname)
		err := replicasetsobj.Delete(commonname, &meta_v1.DeleteOptions{})
		if err != nil {
			log.Warnf("Cannot delete ReplicaSet: %s", err)
		}
	}else if delete && typ == Job {
		log.Infof("Deleting Job: %s", commonname)
		err := jobsobj.Delete(commonname, &meta_v1.DeleteOptions{})
		if err != nil {
			log.Warnf("Cannot delete Job: %s", err)
		}
	}else if delete && typ == CronJob {
		log.Infof("Deleting CronJob: %s", depname)
		err := cronjobsobj.Delete(depname, &meta_v1.DeleteOptions{})
		if err != nil {
			log.Warnf("Cannot delete CronJob: %s", err)
		}

	} else {
		log.Infof("Deleting Pods: %s", pod.Name)
		podobj := client.CoreV1().Pods(pod.Namespace)
		err := podobj.Delete( pod.Name, &meta_v1.DeleteOptions{})
		if err != nil {
			log.Warnf("Cannot delete Pods: %s", err)
		}

		log.Warnf("delete pods : = %v, type = %v", delete, typ)
	}
}

// check a new pod against xray and extract useful information about it
func getPodInfo(t *HandlerImpl, pod *core_v1.Pod) ([]NotifyComponentPayload, bool, bool, bool, interface{}) {
	components := make([]NotifyComponentPayload, 0)
	recognized := true
	hassecissue := false
	haslicissue := false
	var response  interface{}
	log.Debugf("Pod: %s v.%s (Node: %s, %s)", pod.Name, pod.ObjectMeta.ResourceVersion,
		pod.Spec.NodeName, pod.Status.Phase)
	for _, status := range pod.Status.ContainerStatuses {
		idx := strings.LastIndex(status.ImageID, "sha256:")
		var sha2 string
		if idx != -1 {
			sha2 = status.ImageID[idx+7:]
		} else {
			sha2 = "NA"
		}
		log.Debugf("Container: %s, Digest: %s", status.Image, sha2)
		if sha2 != "NA" && t.url != "" {
			rec, secissue, licissue, resp, err := checkXray(sha2, t.url, t.user, t.pass)
			if err == nil {
				comp := NotifyComponentPayload{Name: status.Image, Checksum: sha2}
				components = append(components, comp)
				recognized = recognized && rec
				hassecissue = hassecissue || secissue
				haslicissue = haslicissue || licissue
				response = resp
			}
		}
	}
	return components, recognized, hassecissue, haslicissue, response
}

// parse the config.yaml file and return its contents
func getConfig(path, path2 string) (Config, error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		file, err = ioutil.ReadFile(path2)
		if err != nil {
			return Config{}, err
		}
	}
	var config Config
	err = yaml.Unmarshal([]byte(file), &config)
	if err != nil {
		return Config{}, err
	}
	return config, nil
}

// parse the xray_config.yaml file and return its contents
func getXrayConfig(path, path2 string) (string, string, string, string, string, error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		file, err = ioutil.ReadFile(path2)
		if err != nil {
			return "", "", "", "", "", err
		}
	}
	var data map[string]string
	err = yaml.Unmarshal([]byte(file), &data)
	if err != nil {
		return "", "", "", "", "", err
	}
	url, urlok := data["url"]
	user, userok := data["user"]
	pass, passok := data["password"]
	if urlok && userok && passok {
		return url, user, pass, data["slackWebhookUrl"], data["xrayWebhookToken"], nil
	}
	return "", "", "", "", "", errors.New("xray_config.yaml does not contain required information")
}

// ComponentPayload is the component structure in ComponentAPIResponse, as well
// as the request payload for the xray violation API.
type ComponentPayload struct {
	Package string `json:"package_id"`
	Version string `json:"version"`
}

// ComponentAPIResponse is the response from the xray component API.
type ComponentAPIResponse struct {
	Checksum   string             `json:"sha256"`
	Components []ComponentPayload `json:"ids"`
}

// ViolationAPIResponseItem is the item structure in a ViolationAPIResponse.
type ViolationAPIResponseItem struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
}

// ViolationAPIResponse is the response from the xray violation API.
type ViolationAPIResponse struct {
	Total int                        `json:"total_count"`
	Data  []ViolationAPIResponseItem `json:"data"`
}

// ask xray about the checksums in a given pod, specifically for any violations
func checkXray(sha2, url, user, pass string) (bool, bool, bool, interface{}, error) {
	apiNotFound := errors.New("404 response, try the backup API instead")
	log.Debugf("Checking sha %s with Xray ...", sha2)
	var data ComponentAPIResponse
	var response interface{}
	 err := func(data *ComponentAPIResponse) (error) {
		client := &http.Client{}
		req, err := http.NewRequest("GET", url+"/api/v1/componentIdsByChecksum/"+sha2, nil)
		if err != nil {
			log.Warnf("Error checking xray: %s", err)
			return  err
		}
		req.SetBasicAuth(user, pass)
		resp, err := client.Do(req)
		if err != nil {
			log.Warnf("Error checking xray: %s", err)
			return  err
		}
		defer resp.Body.Close()
		if resp.StatusCode == 404 {
			return  apiNotFound
		}
		if resp.StatusCode != 200 {
			log.Warnf("Error checking xray: response code is %s", resp.Status)
			return  err
		}


		err = json.NewDecoder(resp.Body).Decode(data)
		if err != nil {
			log.Warnf("Error checking xray: %s", err)
			return  err
		}
		return  nil
	}(&data)
	if err == apiNotFound {
		log.Debug("404 response from componentIdsByChecksum, trying backup API instead")
		return checkXrayBackup(sha2, url, user, pass)
	}
	if err != nil {
		return false, false, false, response, err
	}
	if len(data.Components) <= 0 {

		log.Debug("Xray does not recognize this sha")
		return false, false, false, response, nil
	}
	for _, comp := range data.Components {
		bodyjson, err := json.Marshal(&comp)
		if err != nil {
			log.Warnf("Error checking xray: %s", err)
			return false, false, false, response, err
		}
		var resp ViolationAPIResponse
		err = func(data *ViolationAPIResponse) error {
			client := &http.Client{}
			path := "/ui/userIssues/details?direction=asc&order_by=severity&num_of_rows=0&page_num=0"
			body := bytes.NewReader(bodyjson)
			req, err := http.NewRequest("POST", url+path, body)
			if err != nil {
				log.Warnf("Error checking xray: %s", err)
				return err
			}
			req.SetBasicAuth(user, pass)
			req.Header.Add("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				log.Warnf("Error checking xray: %s", err)
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				log.Warnf("Error checking xray: response code is %s", resp.Status)
				return errors.New("xray server responded with status: " + resp.Status)
			}


			err = json.NewDecoder(resp.Body).Decode(data)
			if err != nil {
				log.Warnf("Error checking xray: %s", err)
				return err
			}

			return nil
		}(&resp)
		response = resp
		if err != nil {
			return false, false, false, response, err
		}
		for _, item := range resp.Data {
			if item.Severity == "High" {
				if item.Type == "security" {
					log.Infof("Major security violation found for sha: %s", sha2)
					return true, true, false, response, nil
				} else if item.Type == "licenses" || item.Type == "license" {
					log.Infof("Major license violation found for sha: %s", sha2)
					return true, false, true, response, nil
				}
			}
		}
	}
	log.Debug("No major security issues found")
	return true, false, false, "No major security issues found", nil
}

// ask xray about the checksums in a given pod, specifically for any issues
func checkXrayBackup(sha2, url, user, pass string) (bool, bool, bool, interface{}, error) {
	log.Debugf("Checking sha %s with Xray ...", sha2)
	client := &http.Client{}
	body := strings.NewReader("{\"checksums\":[\"" + sha2 + "\"]}")
	req, err := http.NewRequest("POST", url+"/api/v1/summary/artifact", body)
	if err != nil {
		log.Warnf("Error checking xray: %s", err)
		return false, false, false, "", err
	}
	req.SetBasicAuth(user, pass)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)

	if err != nil {
		log.Warnf("Error checking xray: %s", err)
		return false, false, false, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Warnf("Error checking xray: response code is %s", resp.Status)
		return false, false, false, "", errors.New("xray server responded with status: " + resp.Status)
	}



	var data interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	dt := data.(map[string]interface{})
	artifacts := dt["artifacts"].([]interface{})
	log.Debug(data)
	if len(artifacts) <= 0 {
		log.Debug("Xray does not recognize this sha")
		return false, false, false, data, nil
	}
	for _, artifact := range artifacts {
		art := artifact.(map[string]interface{})
		issues := art["issues"].([]interface{})
		for _, issue := range issues {
			is := issue.(map[string]interface{})
			typ := is["issue_type"].(string)
			sev := is["severity"].(string)
			if typ == "security" && (sev == "Major" || sev == "Critical" || sev == "High") {
				log.Infof("Major security issue found for sha: %s", sha2)
				return true, true, false, data, nil
			}
			if typ == "license" && (sev == "Major" || sev == "Critical" || sev == "High") {
				log.Infof("Major license issue found for sha: %s", sha2)
				return true, false, true, data, nil
			}
		}
	}
	log.Debug("No major security issues found")
	return true, false, false, "No major security issues found", nil
}
