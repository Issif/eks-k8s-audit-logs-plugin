/*
Copyright (C) 2021 The Falco Authors.

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
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"time"

	"github.com/alecthomas/jsonschema"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/valyala/fastjson"
)

type MyPluginConfig struct {
}

type MyPlugin struct {
	plugins.BasePlugin
	config      MyPluginConfig
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
}

type MyInstance struct {
	source.BaseInstance
	lastTimestamp int64
	Cluster       string // Name of EKS Cluster
	Region        string // Region of EKS Cluster
	Client        *cloudwatchlogs.CloudWatchLogs
}

func init() {
	p := &MyPlugin{}
	extractor.Register(p)
	source.Register(p)
}

func (m *MyPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                 5,
		Name:               "eks-k8s-audit-logs",
		Description:        "K8S Audit Logs of EKS from Cloudwatch Logs",
		Contact:            "github.com/falcosecurity/plugins/",
		Version:            "0.1.0",
		RequiredAPIVersion: "0.3.0",
		EventSource:        "k8s_audit_eks",
	}
}

func (m *MyPlugin) InitSchema() *sdk.SchemaInfo {
	schema, err := jsonschema.Reflect(&MyPluginConfig{}).MarshalJSON()
	if err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

func (m *MyPlugin) Init(config string) error {
	// initialize state
	m.jdataEvtnum = math.MaxUint64
	m.jdata = new(fastjson.Value)
	json.Unmarshal([]byte(config), &m.config)
	return nil
}

func (m *MyPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "ka.auditid", Desc: "The unique id of the audit event"},
		{Type: "string", Name: "ka.stage", Desc: "Stage of the request (e.g. RequestReceived, ResponseComplete, etc.)"},
		{Type: "string", Name: "ka.auth.decision", Desc: "The authorization decision"},
		{Type: "string", Name: "ka.auth.reason", Desc: "The authorization reason"},
		{Type: "string", Name: "ka.user.name", Desc: "The user name performing the request"},
		{Type: "string", Name: "ka.user.groups", Desc: "The groups to which the user belongs"},
		{Type: "string", Name: "ka.impuser.name", Desc: "The impersonated user name"},
		{Type: "string", Name: "ka.verb", Desc: "The action being performed"},
		{Type: "string", Name: "ka.uri", Desc: "The request URI as sent from client to server"},
		{Type: "string", Name: "ka.uri.param", Desc: "The value of a given query parameter in the uri (e.g. when uri=/foo?key=val, ka.uri.param[key] is val). (IDX_REQUIRED, IDX_KEY)"},
		{Type: "string", Name: "ka.target.name", Desc: "The target object name"},
		{Type: "string", Name: "ka.target.namespace", Desc: "The target object namespace"},
		{Type: "string", Name: "ka.target.resource", Desc: "The target object resource"},
		{Type: "string", Name: "ka.target.subresource", Desc: "The target object subresource"},
		{Type: "string", Name: "ka.req.binding.subjects", Desc: "When the request object refers to a cluster role binding, the subject (e.g. account/users) being linked by the binding"},
		{Type: "string", Name: "ka.req.binding.role", Desc: "When the request object refers to a cluster role binding, the role being linked by the binding"},
		{Type: "string", Name: "ka.req.binding.subject.has_name", Desc: "Deprecated, always returns \"N/A\". Only provided for backwards compatibility (IDX_REQUIRED, IDX_KEY)"},
		{Type: "string", Name: "ka.req.configmap.name", Desc: "If the request object refers to a configmap, the configmap name"},
		{Type: "string", Name: "ka.req.configmap.obj", Desc: "If the request object refers to a configmap, the entire configmap object"},
		{Type: "string", Name: "ka.req.pod.containers.image", Desc: "When the request object refers to a pod, the container's images. (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.container.image", Desc: "Deprecated by ka.req.pod.containers.image. Returns the image of the first container only"},
		{Type: "string", Name: "ka.req.pod.containers.image.repository", Desc: "The same as req.container.image, but only the repository part (e.g. falcosecurity/falco). (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.container.image.repository", Desc: "Deprecated by ka.req.pod.containers.image.repository. Returns the repository of the first container only"},
		{Type: "string", Name: "ka.req.pod.host_ipc", Desc: "When the request object refers to a pod, the value of the hostIPC flag."},
		{Type: "string", Name: "ka.req.pod.host_network", Desc: "When the request object refers to a pod, the value of the hostNetwork flag."},
		{Type: "string", Name: "ka.req.container.host_network", Desc: "Deprecated alias for ka.req.pod.host_network"},
		{Type: "string", Name: "ka.req.pod.host_pid", Desc: "When the request object refers to a pod, the value of the hostPID flag."},
		{Type: "string", Name: "ka.req.pod.containers.host_port", Desc: "When the request object refers to a pod, all container's hostPort values. (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.pod.containers.privileged", Desc: "When the request object refers to a pod, the value of the privileged flag for all containers. (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.container.privileged", Desc: "Deprecated by ka.req.pod.containers.privileged. Returns true if any container has privileged=true"},
		{Type: "string", Name: "ka.req.pod.containers.allow_privilege_escalation", Desc: "When the request object refers to a pod, the value of the allowPrivilegeEscalation flag for all containers (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.pod.containers.read_only_fs", Desc: "When the request object refers to a pod, the value of the readOnlyRootFilesystem flag for all containers (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.pod.run_as_user", Desc: "When the request object refers to a pod, the runAsUser uid specified in the security context for the pod. See ....containers.run_as_user for the runAsUser for individual containers"},
		{Type: "string", Name: "ka.req.pod.containers.run_as_user", Desc: "When the request object refers to a pod, the runAsUser uid for all containers (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.pod.containers.eff_run_as_user", Desc: "When the request object refers to a pod, the initial uid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no uid is specified (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.pod.run_as_group", Desc: "When the request object refers to a pod, the runAsGroup gid specified in the security context for the pod. See ....containers.run_as_group for the runAsGroup for individual containers"},
		{Type: "string", Name: "ka.req.pod.containers.run_as_group", Desc: "When the request object refers to a pod, the runAsGroup gid for all containers (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.pod.containers.eff_run_as_group", Desc: "When the request object refers to a pod, the initial gid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no gid is specified (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.pod.containers.proc_mount", Desc: "When the request object refers to a pod, the procMount types for all containers (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.role.rules", Desc: "When the request object refers to a role/cluster role, the rules associated with the role"},
		{Type: "string", Name: "ka.req.role.rules.apiGroups", Desc: "When the request object refers to a role/cluster role, the api groups associated with the role's rules (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.role.rules.nonResourceURLs", Desc: "When the request object refers to a role/cluster role, the non resource urls associated with the role's rules (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.role.rules.verbs", Desc: "When the request object refers to a role/cluster role, the verbs associated with the role's rules (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.role.rules.resources", Desc: "When the request object refers to a role/cluster role, the resources associated with the role's rules (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.pod.fs_group", Desc: "When the request object refers to a pod, the fsGroup gid specified by the security context."},
		{Type: "string", Name: "ka.req.pod.supplemental_groups", Desc: "When the request object refers to a pod, the supplementalGroup gids specified by the security context."},
		{Type: "string", Name: "ka.req.pod.containers.add_capabilities", Desc: "When the request object refers to a pod, all capabilities to add when running the container. (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.service.type", Desc: "When the request object refers to a service, the service type"},
		{Type: "string", Name: "ka.req.service.ports", Desc: "When the request object refers to a service, the service's ports (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.pod.volumes.hostpath", Desc: "When the request object refers to a pod, all hostPath paths specified for all volumes (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.volume.hostpath", Desc: "Deprecated by ka.req.pod.volumes.hostpath. Return true if the provided (host) path prefix is used by any volume (IDX_ALLOWED, IDX_KEY)"},
		{Type: "string", Name: "ka.req.pod.volumes.flexvolume_driver", Desc: "When the request object refers to a pod, all flexvolume drivers specified for all volumes (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.req.pod.volumes.volume_type", Desc: "When the request object refers to a pod, all volume types for all volumes (IDX_ALLOWED, IDX_NUMERIC)"},
		{Type: "string", Name: "ka.resp.name", Desc: "The response object name"},
		{Type: "uint64", Name: "ka.response.code", Desc: "The response code"},
		{Type: "string", Name: "ka.response.reason", Desc: "The response reason (usually present only for failures)"},
		{Type: "string", Name: "ka.useragent", Desc: "The useragent of the client who made the request to the apiserver"},
	}
}

func (p *MyPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	// Decode the json, but only if we haven't done it yet for this event
	if evt.EventNum() != p.jdataEvtnum {
		// Read the event data
		data, err := ioutil.ReadAll(evt.Reader())
		if err != nil {
			fmt.Println(err.Error())
			return err
		}

		// Maybe temp--remove trailing null bytes from string
		data = bytes.Trim(data, "\x00")

		// For this plugin, events are always strings
		evtStr := string(data)

		p.jdata, err = p.jparser.Parse(evtStr)
		if err != nil {
			// Not a json file, so not present.
			return err
		}
		p.jdataEvtnum = evt.EventNum()
	}

	// Extract the field value
	var present bool
	var value interface{}
	if req.FieldType() == sdk.ParamTypeUint64 {
		present, value = getfieldU64(p.jdata, req.Field())
	} else {
		present, value = getfieldStr(p.jdata, req.Field())
	}
	if present {
		req.SetValue(value)
	}

	return nil
}

func (m *MyPlugin) Open(params string) (source.Instance, error) {
	var obj map[string]string
	err := json.Unmarshal([]byte(params), &obj)
	if err != nil {
		return nil, fmt.Errorf("params %s could not be parsed: %v", params, err)
	}
	if _, ok := obj["cluster"]; !ok {
		return nil, fmt.Errorf("params %s did not contain cluster property", params)
	}

	mysession := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	return &MyInstance{
		Client:        cloudwatchlogs.New(mysession, aws.NewConfig().WithRegion(obj["region"])),
		Cluster:       obj["cluster"],
		Region:        obj["region"],
		lastTimestamp: time.Now().Add(-10 * time.Second).Unix(),
	}, nil
}

func (m *MyPlugin) String(in io.ReadSeeker) (string, error) {
	var value string
	encoder := gob.NewDecoder(in)
	if err := encoder.Decode(&value); err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", value), nil
}

func (m *MyInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	logs, err := m.Client.FilterLogEvents(&cloudwatchlogs.FilterLogEventsInput{
		LogGroupName:        aws.String("/aws/eks/" + m.Cluster + "/cluster"),
		LogStreamNamePrefix: aws.String("kube-apiserver-audit"),
		Limit:               aws.Int64(int64(evts.Len())),
		StartTime:           aws.Int64(m.lastTimestamp),
	})
	if err != nil {
		fmt.Println(err.Error())
		return 0, sdk.ErrEOF
	}
	for n := 0; n < evts.Len() && n < len(logs.Events); n++ {
		evt := evts.Get(n)
		log := logs.Events[n]

		evt.SetTimestamp(uint64(time.Now().UnixNano()))

		_, err := evt.Writer().Write([]byte(*log.Message))
		if err != nil {
			return 0, err
		}
	}
	time.Sleep(1 * time.Second)
	return len(logs.Events), nil
}

func main() {}
