# Tekton CI/CD Pipeline for ATAuth Gateway

This directory contains Tekton pipeline resources for building and deploying ATAuth Gateway on a k3s cluster.

## Prerequisites

1. **Tekton Pipelines** installed on your k3s cluster:
   ```bash
   kubectl apply -f https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml
   ```

2. **Tekton Triggers** for webhook support:
   ```bash
   kubectl apply -f https://storage.googleapis.com/tekton-releases/triggers/latest/release.yaml
   kubectl apply -f https://storage.googleapis.com/tekton-releases/triggers/latest/interceptors.yaml
   ```

3. **Tekton Dashboard** (optional but recommended):
   ```bash
   kubectl apply -f https://storage.googleapis.com/tekton-releases/dashboard/latest/release.yaml
   ```

## Setup

### 1. Configure Registry Credentials

Create a secret for your container registry:

```bash
kubectl create secret docker-registry registry-credentials \
  --docker-server=gitea.cloudforest-basilisk.ts.net \
  --docker-username=<your-username> \
  --docker-password=<your-password-or-token> \
  -n tekton-pipelines
```

Or edit `secrets.yaml` with your credentials and apply.

### 2. Configure Git Credentials (if private repo)

```bash
kubectl create secret generic git-credentials \
  --from-literal=username=<your-username> \
  --from-literal=password=<your-token> \
  -n tekton-pipelines
```

### 3. Apply Pipeline Resources

```bash
# Apply all Tekton resources
kubectl apply -k tekton/

# Or apply individually
kubectl apply -f tekton/rbac.yaml
kubectl apply -f tekton/pipeline.yaml
kubectl apply -f tekton/trigger.yaml
kubectl apply -f tekton/ingress.yaml
```

### 4. Configure Gitea Webhook

In your Gitea repository settings, add a webhook:

- **URL**: `https://tekton-webhook.cloudforest-basilisk.ts.net/atauth`
- **Content Type**: `application/json`
- **Secret**: (optional, add CEL interceptor if using)
- **Events**: Push events

## Usage

### Manual Pipeline Run

Trigger a build manually:

```bash
kubectl create -f tekton/pipelinerun.yaml
```

Or with custom parameters:

```bash
cat <<EOF | kubectl create -f -
apiVersion: tekton.dev/v1beta1
kind: PipelineRun
metadata:
  generateName: atauth-gateway-build-
  namespace: tekton-pipelines
spec:
  pipelineRef:
    name: atauth-gateway-build
  params:
    - name: git-revision
      value: "develop"
    - name: image-tag
      value: "dev-$(date +%Y%m%d-%H%M%S)"
  workspaces:
    - name: source
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 1Gi
    - name: docker-credentials
      secret:
        secretName: registry-credentials
EOF
```

### Monitor Pipeline Runs

```bash
# List pipeline runs
kubectl get pipelineruns -n tekton-pipelines

# Watch logs
kubectl logs -f -n tekton-pipelines -l tekton.dev/pipelineRun=<run-name>

# Or use tkn CLI
tkn pipelinerun logs -f -n tekton-pipelines
```

### Tekton Dashboard

If installed, access the dashboard:

```bash
kubectl port-forward -n tekton-pipelines svc/tekton-dashboard 9097:9097
```

Then open http://localhost:9097

## Pipeline Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  fetch-source   │────▶│   build-push    │────▶│     deploy      │
│  (git-clone)    │     │    (kaniko)     │     │ (kubectl apply) │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

1. **fetch-source**: Clones the Git repository
2. **build-push**: Builds Docker image with Kaniko and pushes to registry
3. **deploy**: Applies Kubernetes manifests with new image tag

## Files

| File | Description |
|------|-------------|
| `pipeline.yaml` | Main pipeline definition |
| `pipelinerun.yaml` | Example manual run |
| `trigger.yaml` | Webhook trigger configuration |
| `rbac.yaml` | Service accounts and permissions |
| `secrets.yaml` | Registry and Git credentials template |
| `ingress.yaml` | Ingress for webhook endpoint |
| `kustomization.yaml` | Kustomize configuration |

## Troubleshooting

### Build fails with permission denied

Ensure the PVC has correct permissions:
```yaml
podTemplate:
  securityContext:
    fsGroup: 65532
```

### Kaniko can't push to registry

Verify registry credentials:
```bash
kubectl get secret registry-credentials -n tekton-pipelines -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d
```

### Webhook not triggering

Check EventListener pods:
```bash
kubectl get pods -n tekton-pipelines -l eventlistener=atauth-gateway-listener
kubectl logs -n tekton-pipelines -l eventlistener=atauth-gateway-listener
```
