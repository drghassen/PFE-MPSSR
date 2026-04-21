#!/busybox/sh
set -euo pipefail

mkdir -p /kaniko/.docker
printf '{"auths":{"%s":{"username":"%s","password":"%s"}}}' \
  "$CI_REGISTRY" "$CI_REGISTRY_USER" "$CI_REGISTRY_PASSWORD" > /kaniko/.docker/config.json
/kaniko/executor \
  --context "${CI_PROJECT_DIR}" \
  --dockerfile "${CI_PROJECT_DIR}/ci/images/opa/Dockerfile" \
  --destination "${CI_REGISTRY_IMAGE}/opa:${OPA_BUILD_TAG:-${CI_COMMIT_SHA}}" \
  --build-arg "OPA_VERSION=${OPA_VERSION:-1.13.1}" \
  --snapshot-mode=redo \
  --cache=true \
  --cache-repo "${CI_REGISTRY_IMAGE}/cache/opa"
