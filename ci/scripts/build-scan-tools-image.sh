#!/busybox/sh
mkdir -p /kaniko/.docker
printf '{"auths":{"%s":{"username":"%s","password":"%s"}}}' \
  "$CI_REGISTRY" "$CI_REGISTRY_USER" "$CI_REGISTRY_PASSWORD" > /kaniko/.docker/config.json
/kaniko/executor \
  --context "${CI_PROJECT_DIR}" \
  --dockerfile "${CI_PROJECT_DIR}/ci/images/scan-tools/Dockerfile" \
  --destination "${CI_REGISTRY_IMAGE}/scan-tools:${SCAN_TOOLS_BUILD_TAG:-1.0.0}" \
  --build-arg "GITLEAKS_VERSION=${GITLEAKS_VERSION}" \
  --build-arg "CHECKOV_VERSION=${CHECKOV_VERSION}" \
  --build-arg "TRIVY_VERSION=${TRIVY_VERSION}" \
  --build-arg "JSONSCHEMA_VERSION=${JSONSCHEMA_VERSION}" \
  --snapshot-mode=redo \
  --cache=true \
  --cache-repo "${CI_REGISTRY_IMAGE}/cache/scan-tools"
