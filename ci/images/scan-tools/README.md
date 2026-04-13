# CloudSentinel Scan Tools Image

Prebuilt CI image used by scanner jobs to avoid per-job setup time.

Included tools (pinned):
- gitleaks `8.21.2`
- checkov `3.2.502`
- trivy `0.69.1`
- jsonschema `4.25.1`
- jq, bash, curl, git, tar, gzip

Build/push (local):

```bash
docker build -f ci/images/scan-tools/Dockerfile -t registry.gitlab.com/drghassen/pfe-cloud-sentinel/scan-tools:1.0.0 .
docker push registry.gitlab.com/drghassen/pfe-cloud-sentinel/scan-tools:1.0.0
```
