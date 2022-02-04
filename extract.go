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
	"github.com/valyala/fastjson"
)

func getfieldStr(jdata *fastjson.Value, field string) (bool, string) {
	var val []byte

	switch field {
	case "ka.auditid":
		val = jdata.GetStringBytes("auditID")
	case "ka.stage":
		val = jdata.GetStringBytes("stage")
	case "ka.auth.decision":
		val = jdata.GetStringBytes("annotations", "authorization.k8s.io/decision")
	case "ka.auth.reason":
		val = jdata.GetStringBytes("annotations", "authorization.k8s.io/reason")
	case "ka.user.name":
		val = jdata.GetStringBytes("user", "username")
	case "ka.user.groups":
		val = jdata.GetStringBytes("user", "groups")
	case "ka.impuser.name":
		val = jdata.GetStringBytes("impersonatedUser", "username")
	case "ka.verb":
		val = jdata.GetStringBytes("verb")
	case "ka.uri":
		val = jdata.GetStringBytes("requestURI")
	case "ka.uri.param":
		// todo
	case "ka.target.name":
		val = jdata.GetStringBytes("objectRef", "name")
	case "ka.target.namespace":
		val = jdata.GetStringBytes("objectRef", "namespace")
	case "ka.target.resource":
		val = jdata.GetStringBytes("objectRef", "resource")
	case "ka.target.subresource":
		val = jdata.GetStringBytes("objectRef", "subresource")
	case "ka.req.binding.subjects":
		val = jdata.GetStringBytes("requestObject", "subjects")
	case "ka.req.binding.role":
		val = jdata.GetStringBytes("requestObject", "roleRef", "name")
	case "ka.req.binding.subject.has_name":
		// todo
	case "ka.req.configmap.name":
		val = jdata.GetStringBytes("objectRef", "name")
	case "ka.req.configmap.obj":
		val = jdata.GetStringBytes("requestObject", "data")
	case "ka.req.pod.containers.image":
		// todo
	case "ka.req.container.image":
		// todo
	case "ka.req.pod.containers.image.repository":
		// todo
	case "ka.req.container.image.repository":
		// todo
	case "ka.req.pod.host_ipc":
		val = jdata.GetStringBytes("requestObject", "spec", "hostIPC")
	case "ka.req.pod.host_network":
		val = jdata.GetStringBytes("requestObject", "spec", "hostNetwork")
	case "ka.req.container.host_network":
		val = jdata.GetStringBytes("requestObject", "spec", "hostNetwork")
	case "ka.req.pod.host_pid":
		// todo
	case "ka.req.pod.containers.host_port":
		val = jdata.GetStringBytes("requestObject", "spec", "hostPID")
	case "ka.req.pod.containers.privileged":
		// todo
	case "ka.req.container.privileged":
		// todo
	case "ka.req.pod.containers.allow_privilege_escalation":
		// todo
	case "ka.req.pod.containers.read_only_fs":
		// todo
	case "ka.req.pod.run_as_user":
		val = jdata.GetStringBytes("requestObject", "spec", "securityContext", "runAsUser")
	case "ka.req.pod.containers.run_as_user":
		// todo
	case "ka.req.pod.containers.eff_run_as_user":
		// todo
	case "ka.req.pod.run_as_group":
		val = jdata.GetStringBytes("requestObject", "spec", "securityContext", "runAsGroup")
	case "ka.req.pod.containers.run_as_group":
		// todo
	case "ka.req.pod.containers.eff_run_as_group":
		// todo
	case "ka.req.pod.containers.proc_mount":
		// todo
	case "ka.req.role.rules":
		val = jdata.GetStringBytes("requestObject", "rules")
	case "ka.req.role.rules.apiGroups":
		// todo
	case "ka.req.role.rules.nonResourceURLs":
		// todo
	case "ka.req.role.rules.verbs":
		// todo
	case "ka.req.role.rules.resources":
		// todo
	case "ka.req.pod.fs_group":
		val = jdata.GetStringBytes("requestObject", "spec", "securityContext", "fsGroup")
	case "ka.req.pod.supplemental_groups":
		// todo
	case "ka.req.pod.containers.add_capabilities":
		// todo
	case "ka.req.service.type":
		val = jdata.GetStringBytes("requestObject", "spec", "type")
	case "ka.req.service.ports":
		val = jdata.GetStringBytes("requestObject", "spec", "ports")
	case "ka.req.volume.hostpath":
		// todo
	case "ka.req.pod.volumes.hostpath":
		// todo
	case "ka.req.pod.volumes.flexvolume_driver":
		// todo
	case "ka.req.pod.volumes.volume_type":
		// todo
	case "ka.resp.name":
		val = jdata.GetStringBytes("responseObject", "metadata", "name")
	case "ka.response.reason":
		val = jdata.GetStringBytes("responseStatus", "reason")
	case "ka.useragent":
		val = jdata.GetStringBytes("userAgent")
	default:
		return false, ""
	}

	if val != nil {
		return true, string(val)
	}
	return false, ""
}

func getfieldU64(jdata *fastjson.Value, field string) (bool, uint64) {
	switch field {
	case "ka.response.code":
		val := jdata.Get("responseStatus", "code")
		if val != nil {
			return true, val.GetUint64()
		}
		return false, 0
	default:
		return false, 0
	}
}
