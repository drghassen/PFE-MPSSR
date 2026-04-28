# CloudSentinel Prowler Tools Image

Prebuilt CI image used by shift-right Prowler jobs.

Included tools (pinned):
- prowler `5.24.4`
- jq, bash, curl, git

Build/push (local):

```bash
docker build -f ci/images/prowler-tools/Dockerfile -t registry.gitlab.com/drghassen/pfe-cloud-sentinel/prowler-tools:1.0.0 .
docker push registry.gitlab.com/drghassen/pfe-cloud-sentinel/prowler-tools:1.0.0
```
