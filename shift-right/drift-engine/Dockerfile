FROM python:3.11-slim

ARG TERRAFORM_VERSION=1.8.5
ARG TOFU_VERSION=1.7.2

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TF_IN_AUTOMATION=1 \
    TF_INPUT=0

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl unzip tini \
  && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" -o /tmp/terraform.zip \
  && unzip /tmp/terraform.zip -d /usr/local/bin \
  && rm -f /tmp/terraform.zip \
  && terraform -version

RUN curl -fsSL "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_amd64.zip" -o /tmp/tofu.zip \
  && unzip /tmp/tofu.zip -d /usr/local/bin \
  && rm -f /tmp/tofu.zip \
  && tofu version

RUN pip install --no-cache-dir \
    azure-identity==1.16.1 \
    azure-mgmt-resource==23.1.1 \
    jinja2==3.1.4 \
    pydantic==2.7.4 \
    pyyaml==6.0.2 \
    requests==2.32.3 \
    structlog==24.2.0

COPY . /app

RUN useradd -m -u 10001 appuser \
  && mkdir -p /work/output \
  && chown -R appuser:appuser /work \
  && chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["/usr/bin/tini","--","python","/app/drift-engine.py"]
CMD ["--config","/app/config/drift_config.yaml"]
