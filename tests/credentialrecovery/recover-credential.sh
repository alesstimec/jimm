#!/bin/bash

# Disaster-recovery test: a cloud credential secret is lost from Vault, but the
# controller still holds it. `jaas recover-model-credential` fetches it back
# from the controller (via CredentialContents) and writes it into Vault again.
#
# Uses a microk8s cloud credential (auth-type oauth2, i.e. a bearer Token) whose
# secret the Juju controller DOES return via CredentialContents - unlike an LXD
# 'certificate' credential, whose secret the controller never hands back.
#
# Prerequisite: a microk8s-backed JAAS env, e.g.  ./local/jimm/qa-microk8s.sh

set -euo pipefail
source ./local/jimm/detect-jaas.sh

# Force the local dev Vault creds (a stale VAULT_TOKEN in the shell causes 403s).
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="root"

OWNER="$(juju whoami --format json | jq -r .user)"
CLOUD="${CLOUD:-microk8s}"                              # k8s cloud on the JIMM controller
CRED_NAME="${CRED_NAME:-microk8s}"                      # cloud credential name
CRED_TAG="${CLOUD}/${OWNER}/${CRED_NAME}"               # cloud/owner/name
VAULT_PATH="jimm-kv/creds/${CLOUD}/${OWNER}/${CRED_NAME}" # JIMM's vault layout

echo "0. Secret currently in Vault (before the outage)"
vault kv get "${VAULT_PATH}"

echo "1. Delete the secret from Vault (simulate the outage)"
vault kv metadata delete "${VAULT_PATH}"

echo "1b. Prove the content is gone: show-credential --show-secrets must FAIL"
if juju show-credential "${CLOUD}" "${CRED_NAME}" --show-secrets 2>show-cred.err; then
    echo "   UNEXPECTED: show-credential returned secrets after Vault deletion" >&2
    rm -f show-cred.err
    exit 1
fi
echo "   show-credential failed as expected:"
sed 's/^/     /' show-cred.err
rm -f show-cred.err


echo "3. Recover it from the controller via JIMM"
${JAAS} recover-model-credential "${CRED_TAG}"

echo "4. Confirm it's back in Vault at the same path (secret restored)"
vault kv get "${VAULT_PATH}"

echo "5. Exercise it: add-model must now SUCCEED (JIMM reads Vault and pushes the credential to the controller)"
juju add-model recover-fixed "${CLOUD}"
juju destroy-model recover-fixed --no-prompt --force >/dev/null 2>&1 || true

echo "6. Prove the secret content itself is restored: show-credential --show-secrets reads it back through JIMM"
juju show-credential "${CLOUD}" "${CRED_NAME}" --show-secrets

echo "SUCCESS"
