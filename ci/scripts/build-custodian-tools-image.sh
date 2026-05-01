#!/busybox/sh
set -euo pipefail

mkdir -p /kaniko/.docker
printf '{"auths":{"%s":{"username":"%s","password":"%s"}}}' \
  "$CI_REGISTRY" "$CI_REGISTRY_USER" "$CI_REGISTRY_PASSWORD" > /kaniko/.docker/config.json
/kaniko/executor \
  --context "${CI_PROJECT_DIR}" \
  --dockerfile "${CI_PROJECT_DIR}/ci/images/custodian-tools/Dockerfile" \
  --destination "${CI_REGISTRY_IMAGE}/custodian-tools:${CUSTODIAN_TOOLS_BUILD_TAG:-1.0.0}" \
  --build-arg "C7N_VERSION=${C7N_VERSION:-0.9.43}" \
  --build-arg "C7N_AZURE_VERSION=${C7N_AZURE_VERSION:-0.7.49}" \
  --snapshot-mode=redo \
  --cache=true \
  --cache-repo "${CI_REGISTRY_IMAGE}/cache/custodian-tools"
