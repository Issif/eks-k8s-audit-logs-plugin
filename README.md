# EKS K8S Audit Logs Plugin

This is a POC for a `Falco Plugin` allowing to gather logs and trigger events for `k8s audit` of a `EKS Cluster`. It scrapes last logs for `EKS` from `Cloudwatch Logs`, parse them and send them to `Plugin Framework` with correct fields.

> :warning: This is a POC, don't use in Production, join us on Slack **kubernetes#falco** to discuss about.


## Requirements

You need:
* `Go` >= 1.17
* `Falco` >= 0.31
* `json` plugin for `Falco` 

## Build

```shell
make
```

## Configurations

* Authentication to `AWS`:
  * this plugin uses `aws-sdk-go` for authentication and collect of logs from `Cloudwatch Logs`
  * you can export `AWS_ACCESS_KEY_ID`

* `falco.yaml`

```yaml
plugins:
  - name: eks-k8s-audit-logs
    library_path: /etc/falco/audit/libeks-k8s-audit-logs.so
    init_config: ''
    open_params: '{"cluster": "clusterName", "region": "eu-west-1"}'
  - name: json
    library_path: /etc/falco/json/libjson.so
    init_config: ""

load_plugins: [eks-k8s-audit-logs,json]

stdout_output:
  enabled: true
```

* `rules.yaml`

> :warning: There's currently a conflict with `k8s_audit` source already built in `Falco`, it enforces the usage of `jevt` extractor but it can't work with this plugin and makes `Falco` crash:
> ```shell
> Runtime error: invalid formatting token jevt.time:
> ```
> The solution is to set a different `event_source` for this plugin and change the `source:` setting of rules, see `k8s_audit_rules.yaml` of this repo.
> This issue will be fix asap by removing the `k8s_audit` refs from core.

## Usage

```shell
falco -c falco.yaml -r k8s_audit_rules.yaml
```

## Results

```shell
17:40:05.865829249: Warning K8s Operation performed by user not in allowed list of users (user=eks:certificate-controller target=eks-certificates-controller/configmaps verb=get uri=/api/v1/namespaces/kube-system/configmaps/eks-certificates-controller resp=200)
17:40:05.865862951: Warning K8s Operation performed by user not in allowed list of users (user=eks:certificate-controller target=eks-certificates-controller/configmaps verb=update uri=/api/v1/namespaces/kube-system/configmaps/eks-certificates-controller resp=200)
17:40:07.487729013: Warning K8s Operation performed by user not in allowed list of users (user=eks:certificate-controller target=eks-certificates-controller/configmaps verb=get uri=/api/v1/namespaces/kube-system/configmaps/eks-certificates-controller resp=200)
17:40:07.487766347: Warning K8s Operation performed by user not in allowed list of users (user=eks:certificate-controller target=eks-certificates-controller/configmaps verb=update uri=/api/v1/namespaces/kube-system/configmaps/eks-certificates-controller resp=200)
17:40:07.488135947: Warning K8s Operation performed by user not in allowed list of users (user=eks:certificate-controller target=eks-certificates-controller/configmaps verb=get uri=/api/v1/namespaces/kube-system/configmaps/eks-certificates-controller resp=200)

Events detected: 5
Rule counts by severity:
   WARNING: 5
Triggered rules by rule name:
   Disallowed K8s User: 5
Syscall event drop monitoring:
   - event drop detected: 0 occurrences
   - num times actions taken: 0
```