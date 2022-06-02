# Demo: Using Authorino as ValidatingWebhook service to validate other AuthConfigs applied to the cluster

Authorino provides an interface for raw HTTP external authorization requests. This interface can be used for integrations other than the typical Envoy gRPC protocol, such as using Authorino as a generic Kubernetes ValidatingWebhook service.

The rules to validate a request to the Kubernetes API – typically a `POST`, `PUT` or `DELETE` request targeting a particular Kubernetes resource or collection –, according to which either the change will be deemed accepted or not, are written in an Authorino `AuthConfig` custom resource. Authentication and authorization are performed by the Kubernetes API server as usual, with auth features of Authorino implementing the aditional validation within the scope of an `AdmissionReview` request.

This user guide provides an example of using Authorino as a Kubernetes ValidatingWebhook service that validates requests to `CREATE` and `UPDATE` Authorino `AuthConfig` resources. In other words, we will use Authorino as a validator inside the cluster that decides what is a valid AuthConfig for any application which wants to rely on Authorino to protect itself.

**The AuthConfig to validate other AuthConfigs will enforce the following rules:**
- Only 'oidc' identity method can be used
- Using Dex SSO server requires additional permission for the user defined in the Kubernetes RBAC

For convinience, the same instance of Authorino used to enforce the AuthConfig associated with the validating webhook will also be targeted for the sample AuthConfigs created to test the validation. For using different instances of Authorino for the validating webhook and for protecting applications behind a proxy, check out the section about [sharding](./../architecture.md#sharding) in the docs. There is also a [user guide](./sharding.md) on the topic, with concrete examples.

<br/>

## Requirements

- [Docker](https://docs.docker.com/engine/install/)
- [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)

## 1. Create the cluster: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kind%20create%20cluster%20--name%20authorino-demo))

```sh
kind create cluster --name authorino-demo
```

(Optional) Start watching the workloads in a separate terminal: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=watch$$watch%20-n%203%20%22kubectl%20get%20pods%20--all-namespaces%20--user=kind-authorino-demo%20%7C%20grep%20-viE%20'Completed%7COOMKilled'%22))

```sh
watch -n 3 "kubectl get pods --all-namespaces --user=kind-authorino-demo | grep -viE 'Completed|OOMKilled'"
```

## 2. Deploy the SSO servers

Deploy Keycloak: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20create%20namespace%20keycloak%0Akubectl%20-n%20keycloak%20apply%20-f%20https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml))

```sh
kubectl create namespace keycloak
kubectl -n keycloak apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml
```

Deploy Dex: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20create%20namespace%20dex%0Akubectl%20-n%20dex%20apply%20-f%20https://raw.githubusercontent.com/kuadrant/authorino-examples/main/dex/dex-deploy.yaml))

```sh
kubectl create namespace dex
kubectl -n dex apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/dex/dex-deploy.yaml
```

## 3. Install cert-manager ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20apply%20-f%20https://github.com/jetstack/cert-manager/releases/download/v1.4.0/cert-manager.yaml))

```sh
kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.4.0/cert-manager.yaml
```

## 4. Install the Authorino Operator ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20apply%20-f%20https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml))

```sh
kubectl apply -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```

## 5. Deploy Authorino

Create the namespace: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20create%20namespace%20authorino))

```sh
kubectl create namespace authorino
```

Create the TLS certificates: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$curl%20-sSL%20https://raw.githubusercontent.com/Kuadrant/authorino/main/deploy/certs.yaml%20%7C%20sed%20%22s/%5C$(AUTHORINO_INSTANCE)/authorino/g;s/%5C$(NAMESPACE)/authorino/g%22%20%7C%20kubectl%20-n%20authorino%20apply%20-f%20-))

```sh
curl -sSL https://raw.githubusercontent.com/Kuadrant/authorino/main/deploy/certs.yaml | sed "s/\$(AUTHORINO_INSTANCE)/authorino/g;s/\$(NAMESPACE)/authorino/g" | kubectl -n authorino apply -f -
```

Create the Authorino instance: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20-n%20authorino%20apply%20-f%20https://raw.githubusercontent.com/guicassolato/authorino-validating-webhook/main/manifests/authorino.yaml))

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: operator.authorino.kuadrant.io/v1beta1
kind: Authorino
metadata:
  name: authorino
spec:
  clusterWide: true
  listener:
    ports:
      http: 5001 # for admissionreview requests sent by the kube-api-server
    tls:
      certSecretRef:
        name: authorino-server-cert
  oidcServer:
    tls:
      certSecretRef:
        name: authorino-oidc-server-cert
EOF
```

## 6. Define the rules to validate the `AuthConfig` CRs

Create the AuthConfig: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20-n%20authorino%20apply%20-f%20https://raw.githubusercontent.com/guicassolato/authorino-validating-webhook/main/manifests/authconfig-validator.yaml))

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: authconfig-validator
spec:
  # admissionreview requests will be sent to this host name
  hosts:
  - authorino-authorino-authorization.authorino.svc

  # because we're using a single authorino instance for the validating webhook and to protect the user applications,
  # skip operations related to this one authconfig in the 'authorino' namespace
  when:
  - selector: context.request.http.body.@fromstr|request.object.metadata.namespace
    operator: neq
    value: authorino

  # kubernetes admissionreviews carry info about the authenticated user
  identity:
  - name: k8s-userinfo
    plain:
      authJSON: context.request.http.body.@fromstr|request.userInfo

  authorization:
  - name: check-identity
    opa:
      allValues: true
      inlineRego: |
        authconfig = json.unmarshal(input.context.request.http.body).request.object
        forbidden { authconfig.spec.identity[_].apiKey }
        forbidden { authconfig.spec.identity[_].oauth2 }
        forbidden { authconfig.spec.identity[_].kubernetes }
        forbidden { authconfig.spec.identity[_].plain }
        forbidden { authconfig.spec.identity[_].anonymous }
        using_dex { startswith(authconfig.spec.identity[_].oidc.endpoint, "http://dex") }
        allow { count(authconfig.spec.identity) > 0; not forbidden }

  - name: k8s-rbac
    priority: 1 # so it waits for the opa policy first
    when:
    - selector: auth.authorization.check-identity.using_dex
      operator: eq
      value: "true"
    kubernetes:
      user:
        valueFrom: { authJSON: auth.identity.username }
      resourceAttributes:
        namespace: { value: authorino }
        group: { value: sso.company.com }
        resource: { value: dex }
        verb: { value: use }
EOF
```

Define a `Role` to control the usage of Dex: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20-n%20authorino%20apply%20-f%20https://raw.githubusercontent.com/guicassolato/authorino-validating-webhook/main/manifests/role.yaml))

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dex-user
rules:
- apiGroups: ["sso.company.com"]
  resources: ["dex"] # not a real k8s resource
  verbs: ["use"] # not a real k8s verb
EOF
```

## 7. Create the `ValidatingWebhookConfiguration` ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20apply%20-f%20https://raw.githubusercontent.com/guicassolato/authorino-validating-webhook/main/manifests/validatingwebhookconfiguration.yaml))

```sh
kubectl apply -f -<<EOF
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: authconfig-authz
  annotations:
    cert-manager.io/inject-ca-from: authorino/authorino-ca-cert
webhooks:
- name: check-authconfig.authorino.kuadrant.io
  clientConfig:
    service:
      namespace: authorino
      name: authorino-authorino-authorization
      port: 5001
      path: /check
  rules:
  - apiGroups: ["authorino.kuadrant.io"]
    apiVersions: ["v1beta1"]
    resources: ["authconfigs"]
    operations: ["CREATE", "UPDATE"]
    scope: Namespaced
  sideEffects: None
  admissionReviewVersions: ["v1"]
EOF
```

## 8. Create a namespace and Kubernetes user for the next steps

Set the user credentials: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$openssl%20genrsa%20-out%20/tmp/john.key%0Aopenssl%20req%20-new%20-key%20/tmp/john.key%20-out%20/tmp/john.csr%20-subj%20%22/CN=john%22%0Akubectl%20apply%20-f%20https://raw.githubusercontent.com/guicassolato/authorino-validating-webhook/main/manifests/certificatesigningrequest.yaml%0Akubectl%20certificate%20approve%20john%0Akubectl%20get%20csr/john%20-o%20jsonpath='%7B.status.certificate%7D'%20%7C%20base64%20-d%20%3E%20/tmp/john.crt%0Akubectl%20config%20set-credentials%20john%20--client-certificate=/tmp/john.crt%20--client-key=/tmp/john.key%20--embed-certs=true))

```sh
openssl genrsa -out /tmp/john.key
openssl req -new -key /tmp/john.key -out /tmp/john.csr -subj "/CN=john"

kubectl apply -f -<<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: john
spec:
  request: $(cat /tmp/john.csr | base64 | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
  - digital signature
  - key encipherment
  groups:
  - system:authenticated
EOF

kubectl certificate approve john
kubectl get csr/john -o jsonpath='{.status.certificate}' | base64 -d > /tmp/john.crt
kubectl config set-credentials john --client-certificate=/tmp/john.crt --client-key=/tmp/john.key --embed-certs=true
```

Create a namespace and grant permissions for the user: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20create%20namespace%20apps%0Akubectl%20create%20role%20namespace-owner%20--verb=%22*%22%20--resource=%22*.*%22%20-n%20apps%0Akubectl%20create%20rolebinding%20namespace-owners%20--role=namespace-owner%20--user=john%20-n%20apps))

```sh
kubectl create namespace apps
kubectl create role namespace-owner --verb="*" --resource="*.*" -n apps
kubectl create rolebinding namespace-owners --role=namespace-owner --user=john -n apps
```

Set the Kubernetes context: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20config%20set-context%20--current%20--user=john%20--namespace=apps))

```sh
kubectl config set-context --current --user=john --namespace=apps
```

## 9. Try it out

### `AuthConfig` with forbidden identity method ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20apply%20-f%20https://raw.githubusercontent.com/guicassolato/authorino-validating-webhook/main/manifests/myapp-protection-forbidden.yaml))

```sh
kubectl apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  identity:
  - name: api-key
    apiKey:
      labelSelectors: { app: myapp }
EOF
```

### `AuthConfig` with Keycloak ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20apply%20-f%20https://raw.githubusercontent.com/guicassolato/authorino-validating-webhook/main/manifests/myapp-protection-keycloak.yaml))

```sh
kubectl apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  identity:
  - name: keycloak
    oidc:
      endpoint: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant
EOF
```

### `AuthConfig` with Dex

Without permission: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20apply%20-f%20https://raw.githubusercontent.com/guicassolato/authorino-validating-webhook/main/manifests/myapp-protection-dex.yaml))

```sh
kubectl apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  identity:
  - name: keycloak
    oidc:
      endpoint: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant
  - name: dex
    oidc:
      endpoint: http://dex.dex.svc.cluster.local:5556
EOF
```

As admin, grant permission to the user: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20--user=kind-authorino-demo%20-n%20authorino%20apply%20-f%20https://raw.githubusercontent.com/guicassolato/authorino-validating-webhook/main/manifests/rolebinding.yaml))

```sh
kubectl --user=kind-authorino-demo -n authorino apply -f -<<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dex-users
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: dex-user
subjects:
- kind: User
  name: john
EOF
```

Try again with permission: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20apply%20-f%20https://raw.githubusercontent.com/guicassolato/authorino-validating-webhook/main/manifests/myapp-protection-dex.yaml))

```sh
kubectl apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  identity:
  - name: keycloak
    oidc:
      endpoint: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant
  - name: dex
    oidc:
      endpoint: http://dex.dex.svc.cluster.local:5556
EOF
```

## Cleanup ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kind%20delete%20cluster%20--name%20authorino-demo%0Akubectl%20config%20unset%20users.john))

```sh
kind delete cluster --name authorino-demo
kubectl config unset users.john
```
