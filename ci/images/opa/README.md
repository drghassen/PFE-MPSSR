# CloudSentinel OPA CI Image

This image pins the exact OPA version used in CI and adds the tools required
by `shift-left/opa/run-opa.sh` (bash, curl, jq, git).

The Dockerfile uses `openpolicyagent/opa:<version>-static` to avoid libc
compatibility issues on Alpine.

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

## Verify

```bash
docker run --rm $CI_REGISTRY_IMAGE/opa:1.13.1 /usr/local/bin/opa version
docker run --rm $CI_REGISTRY_IMAGE/opa:1.13.1 jq --version
docker run --rm $CI_REGISTRY_IMAGE/opa:1.13.1 bash --version | head -n1
```

## Registry governance checklist

- Enable GitLab container scanning for the repository.
- Enable cleanup policy for old tags and dangling manifests.
- Prefer immutable digests in CI (`OPA_IMAGE=$CI_REGISTRY_IMAGE/opa@sha256:...`).
