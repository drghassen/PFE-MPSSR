#!/busybox/sh
mkdir -p /kaniko/.docker
printf '{"auths":{"%s":{"username":"%s","password":"%s"}}}' \
  "$CI_REGISTRY" "$CI_REGISTRY_USER" "$CI_REGISTRY_PASSWORD" > /kaniko/.docker/config.json
/kaniko/executor \
  --context "${CI_PROJECT_DIR}" \
  --dockerfile "${CI_PROJECT_DIR}/ci/images/deploy-tools/Dockerfile" \
  --destination "${CI_REGISTRY_IMAGE}/deploy-tools:${CI_COMMIT_SHA}" \
  --build-arg "TOFU_VERSION=${TOFU_VERSION}" \
  --build-arg "TOFU_LINUX_AMD64_ZIP_SHA256=${TOFU_LINUX_AMD64_ZIP_SHA256}" \
  --snapshot-mode=redo \
  --cache=true \
  --cache-repo "${CI_REGISTRY_IMAGE}/cache/deploy-tools"
