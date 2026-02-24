# CloudSentinel OPA CI Image

This image pins the exact OPA version used in CI and adds the tools required
by `shift-left/opa/run-opa.sh` (bash, curl, jq, git).

## Build

```bash
docker build \
  --build-arg OPA_VERSION=1.13.1 \
  -t $CI_REGISTRY_IMAGE/opa:1.13.1 \
  ci/images/opa
```

## Push (GitLab Registry)

```bash
docker push $CI_REGISTRY_IMAGE/opa:1.13.1
```
