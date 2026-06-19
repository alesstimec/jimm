#!/bin/bash

# RUN THIS SCRIPT FROM PROJECT ROOT!
#
# This script bootstraps a Juju controller on microk8s and configures the necessary
# config to enable the controller to communicate with the docker compose.
#
# Host-access has some issues, TLDR to fix it:
# 1. enable host-access
# 2. ifconfig 172.16.12.223 (get private address)
# 3. append line: 
#   --node-ip=172.16.12.223
#   to /var/snap/microk8s/current/args/kubelet
# 4. sudo snap restart microk8s

set -euo pipefail

CONTROLLER_NAME="${CONTROLLER_NAME:-qa-microk8s}"
JWKS_DNS="${JWKS_DNS:-jimm.localhost}"
ENABLE_TRACING="${ENABLE_TRACING:-false}"
# Pods inside microk8s reach the host (and docker-published ports) via the docker
# bridge gateway — the same 10.0.1.1 used for JIMM's JWKS endpoint below.
TRACE_ENDPOINT="${TRACE_ENDPOINT:-10.0.1.1:4317}"
TRACE_SAMPLE_RATIO="${TRACE_SAMPLE_RATIO:-1.0}"
TRACE_TAIL_SAMPLING_THRESHOLD="${TRACE_TAIL_SAMPLING_THRESHOLD:-1ns}"

BOOTSTRAP_ARGS=(microk8s "${CONTROLLER_NAME}" --config "login-token-refresh-url=http://10.0.1.1:17070/.well-known/jwks.json")

if [[ "${ENABLE_TRACING,,}" == "true" ]]; then
  echo "Tracing enabled — endpoint: ${TRACE_ENDPOINT}"
  BOOTSTRAP_ARGS+=(
    --config "open-telemetry-enabled=true"
    --config "open-telemetry-endpoint=${TRACE_ENDPOINT}"
    --config "open-telemetry-insecure=true"
    --config "open-telemetry-sample-ratio=${TRACE_SAMPLE_RATIO}"
    --config "open-telemetry-tail-sampling-threshold=${TRACE_TAIL_SAMPLING_THRESHOLD}"
  )
fi

juju bootstrap "${BOOTSTRAP_ARGS[@]}"

if [[ "${ENABLE_TRACING,,}" == "true" ]]; then
  echo "Enabling controller tracing via OTLP gRPC endpoint ${TRACE_ENDPOINT}"
  juju controller-config -c "${CONTROLLER_NAME}" \
    open-telemetry-enabled=true \
    open-telemetry-endpoint="${TRACE_ENDPOINT}" \
    open-telemetry-insecure=true \
    open-telemetry-sample-ratio="${TRACE_SAMPLE_RATIO}" \
    open-telemetry-tail-sampling-threshold="${TRACE_TAIL_SAMPLING_THRESHOLD}"
fi 

