#!/bin/bash

# This script assumes that you have JIMM running with a controller
# named "qa-lxd" attached (can be overriden via BACKING_CONTROLLER_NAME).
#
# This script creates a model via JAAS, deletes that model directly from
# the backing controller, and then verifies the same model can be deleted
# from JAAS via the Juju CLI.
#
# This test covers the case where JAAS still has a database record for a
# model that no longer exists on its backing controller. In that case, a
# Juju CLI destroy-model request through JAAS should clean up the JAAS model
# record successfully.
#
# Usage: ./tests/modeldeletion/delete-from-backing-controller.sh

set -euo pipefail

# Notes:
# - The script creates a model with a random suffix to avoid clashes with
# previous runs.

JIMM_CONTROLLER_NAME="${JIMM_CONTROLLER_NAME:-jimm-dev}"
BACKING_CONTROLLER_NAME="${BACKING_CONTROLLER_NAME:-qa-lxd}"
# Generate a random 4-character suffix for the model name.
RAND_SUFFIX=$(tr -dc 'a-z0-9' </dev/urandom | head -c 4 || true)
MODEL_NAME="deleted-from-backing-$RAND_SUFFIX"

# Source the `JAAS` variable for executing jaas commands.
source "local/jimm/detect-jaas.sh"

# Ensure we start by using the JAAS controller.
echo
echo "Switching to JAAS controller $JIMM_CONTROLLER_NAME"
juju switch "$JIMM_CONTROLLER_NAME"

# Create a model through JAAS using the Juju CLI. The JAAS add-model plugin
# lets us select the target controller so the model is created where this
# test expects to delete it from.
echo
echo "Creating model $MODEL_NAME via JAAS on backing controller $BACKING_CONTROLLER_NAME"
$JAAS add-model "$MODEL_NAME" localhost --target-controller "$BACKING_CONTROLLER_NAME"

# Capture the model UUID so we can address the same model through both
# controllers. Juju 4's show-model response has a qualifier rather than the
# legacy owner field.
echo
model_info=$(juju show-model "$MODEL_NAME" --format json)
model_uuid=$(echo "$model_info" | jq -r ".[\"$MODEL_NAME\"].\"model-uuid\"")
if [[ -z "$model_uuid" || "$model_uuid" == "null" ]]; then
    echo "Unable to determine UUID for model $MODEL_NAME"
    exit 1
fi
echo "Model UUID is $model_uuid"

# Delete the model directly from the backing controller. This simulates JAAS
# having a stale model record after the model has already gone from Juju.
echo
echo "Deleting model $MODEL_NAME directly from backing controller $BACKING_CONTROLLER_NAME"
juju switch "$BACKING_CONTROLLER_NAME"
juju destroy-model "$model_uuid" --no-prompt

# Switch back to JAAS and delete the stale model record through the Juju CLI.
# This is the core behaviour under test: destroy-model should succeed through
# JAAS even though the model has already been deleted from the backing
# controller.
echo
echo "Deleting stale model $MODEL_NAME from JAAS via Juju CLI"
juju switch "$JIMM_CONTROLLER_NAME"
juju destroy-model "$model_uuid" --no-prompt

echo
echo "Model deletion test completed successfully."
exit 0
