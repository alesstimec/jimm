#!/bin/bash

# RUN THIS SCRIPT FROM PROJECT ROOT!
# It will bootstrap a Juju controller and configure the necessary config to enable the controller
# to communicate with the docker compose

set -euo pipefail

CLOUDINIT_FILE=${CLOUDINIT_FILE:-"cloudinit.temp.yaml"}
CONTROLLER_NAME="${CONTROLLER_NAME:-qa-lxd}"
JUJU_BOOTSTRAP_BINARY="${JUJU_BOOTSTRAP_BINARY:-juju}"
SKIP_CONNECT_JIMM="${SKIP_CONNECT_JIMM:-false}"
JWKS_DNS="${JWKS_DNS:-jimm.localhost}"
ENABLE_TRACING="${ENABLE_TRACING:-false}"
TRACE_DNS="${TRACE_DNS:-tempo.local}"
TRACE_ENDPOINT="${TRACE_ENDPOINT:-${TRACE_DNS}:4317}"
TRACE_HOST="${TRACE_ENDPOINT%%:*}"
TRACE_SAMPLE_RATIO="${TRACE_SAMPLE_RATIO:-1.0}"
TRACE_TAIL_SAMPLING_THRESHOLD="${TRACE_TAIL_SAMPLING_THRESHOLD:-1ns}"
HOST_BRIDGE_IP="$(lxc network get lxdbr0 ipv4.address | cut -f1 -d/)"
CLOUDINIT_TEMPLATE=$'cloudinit-userdata: |
  preruncmd:
%s
  ca-certs:
    trusted:
      - |\n%s'

HOSTS_LINES="$(
  printf '    - echo \"%s    %s\" >> /etc/hosts\n' "${HOST_BRIDGE_IP}" "${JWKS_DNS}"
  printf '    - echo \"%s    %s\" >> /etc/hosts\n' "${HOST_BRIDGE_IP}" "${TRACE_HOST}"
)"

# shellcheck disable=SC2059
# We are using the variable as the printf template
printf "$CLOUDINIT_TEMPLATE" "${HOSTS_LINES}" "$(cat local/traefik/certs/ca.crt | sed -e 's/^/        /')" > "${CLOUDINIT_FILE}"
echo "created cloud-init file"

if [ "${SKIP_BOOTSTRAP:-false}" == true ]; then
  echo "skipping controller bootstrap"
  exit 0
fi

BOOTSTRAP_ARGS=(lxd "${CONTROLLER_NAME}" --config "${CLOUDINIT_FILE}")

if [[ "$SKIP_CONNECT_JIMM" != "true" ]]; then
  BOOTSTRAP_ARGS+=(--config "login-token-refresh-url=https://${JWKS_DNS}/.well-known/jwks.json")
else
  echo "Skipping connecting the controller to JIMM"
fi

if [[ -n "${AGENT_VERSION:-}" ]]; then
  BOOTSTRAP_ARGS+=(--agent-version "${AGENT_VERSION}")
fi

if [[ "${ENABLE_TRACING,,}" == "true" ]]; then
  BOOTSTRAP_ARGS+=(
    --config "open-telemetry-enabled=true"
    --config "open-telemetry-endpoint=${TRACE_ENDPOINT}"
    --config "open-telemetry-insecure=true"
    --config "open-telemetry-sample-ratio=${TRACE_SAMPLE_RATIO}"
    --config "open-telemetry-tail-sampling-threshold=${TRACE_TAIL_SAMPLING_THRESHOLD}"
  )
fi

echo "Bootstrapping controller with $JUJU_BOOTSTRAP_BINARY"
JUJU_DEV_FEATURE_FLAGS=ssh-jump "$JUJU_BOOTSTRAP_BINARY" bootstrap "${BOOTSTRAP_ARGS[@]}"

if [[ "${ENABLE_TRACING,,}" == "true" ]]; then
  echo "Enabling controller tracing via OTLP gRPC endpoint ${TRACE_ENDPOINT}"
  juju controller-config -c "${CONTROLLER_NAME}" \
    open-telemetry-enabled=true \
    open-telemetry-endpoint="${TRACE_ENDPOINT}" \
    open-telemetry-insecure=true \
    open-telemetry-sample-ratio="${TRACE_SAMPLE_RATIO}" \
    open-telemetry-tail-sampling-threshold="${TRACE_TAIL_SAMPLING_THRESHOLD}"
fi

rm "$CLOUDINIT_FILE"
