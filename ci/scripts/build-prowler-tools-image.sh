#!/busybox/sh
set -euo pipefail

mkdir -p /kaniko/.docker
printf '{"auths":{"%s":{"username":"%s","password":"%s"}}}' \
  "$CI_REGISTRY" "$CI_REGISTRY_USER" "$CI_REGISTRY_PASSWORD" > /kaniko/.docker/config.json
/kaniko/executor \
  --context "${CI_PROJECT_DIR}" \
  --dockerfile "${CI_PROJECT_DIR}/ci/images/prowler-tools/Dockerfile" \
  --destination "${CI_REGISTRY_IMAGE}/prowler-tools:${PROWLER_TOOLS_BUILD_TAG:-1.0.0}" \
  --build-arg "PROWLER_VERSION=${PROWLER_VERSION:-5.24.4}" \
  --snapshot-mode=redo \
  --cache=true \
  --cache-repo "${CI_REGISTRY_IMAGE}/cache/prowler-tools"
