#!/usr/bin/env bash
# One-off set-up of the real-Azure CI test (run once, e.g. in Azure Cloud
# Shell, as someone who can create app registrations, grant admin consent
# and assign roles on the resource group). Creates:
#   - app "expiry-radar-ci" federated with this GitHub repo (no secret)
#   - a test Key Vault (RBAC) with er-test-cert / er-test-secret / er-test-key
#   - app "expiry-radar-ci-target" with a dummy client secret (Graph test)
#   - Key Vault Reader + Graph Application.Read.All for expiry-radar-ci
# Prints the three/four GitHub repository variables to set.
# Usage: scripts/azure-ci-setup.sh <resource-group> <location> <vault-name> [owner/repo]
set -euo pipefail
RG=$1 LOC=$2 KV=$3 REPO=${4:-Joao-Paulino/expiry-radar}
GRAPH=00000003-0000-0000-c000-000000000000
ROLE=9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30 # Application.Read.All (application)
ME=$(az ad signed-in-user show --query id -o tsv)
TENANT=$(az account show --query tenantId -o tsv)

echo "== CI identity (federated with GitHub, no secret)"
APP=$(az ad app list --display-name expiry-radar-ci --query "[0].appId" -o tsv)
[ -n "$APP" ] || APP=$(az ad app create --display-name expiry-radar-ci --query appId -o tsv)
SP=$(az ad sp show --id "$APP" --query id -o tsv 2>/dev/null || az ad sp create --id "$APP" --query id -o tsv)
for s in ref:refs/heads/main pull_request; do
  name="gh-${s//[:\/]/-}"
  az ad app federated-credential show --id "$APP" --federated-credential-id "$name" >/dev/null 2>&1 ||
    az ad app federated-credential create --id "$APP" --parameters \
      "{\"name\":\"$name\",\"issuer\":\"https://token.actions.githubusercontent.com\",\"subject\":\"repo:$REPO:$s\",\"audiences\":[\"api://AzureADTokenExchange\"]}" >/dev/null
done

echo "== Test Key Vault and items"
az group create -n "$RG" -l "$LOC" >/dev/null
az keyvault show -n "$KV" >/dev/null 2>&1 || az keyvault create -n "$KV" -g "$RG" -l "$LOC" --enable-rbac-authorization true >/dev/null
KVID=$(az keyvault show -n "$KV" --query id -o tsv)
az role assignment create --assignee-object-id "$ME" --assignee-principal-type User --role "Key Vault Administrator" --scope "$KVID" >/dev/null
az role assignment create --assignee-object-id "$SP" --assignee-principal-type ServicePrincipal --role "Key Vault Reader" --scope "$KVID" >/dev/null
echo "   waiting for the role assignment to propagate"; sleep 60
az keyvault certificate create --vault-name "$KV" -n er-test-cert -p "$(az keyvault certificate get-default-policy)" >/dev/null
az keyvault secret set --vault-name "$KV" -n er-test-secret --value dummy --expires "$(date -u -d '+1 year' +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
az keyvault key create --vault-name "$KV" -n er-test-key --expires "$(date -u -d '+1 year' +%Y-%m-%dT%H:%M:%SZ)" >/dev/null

echo "== Graph test target and permission"
TGT=$(az ad app list --display-name expiry-radar-ci-target --query "[0].appId" -o tsv)
[ -n "$TGT" ] || TGT=$(az ad app create --display-name expiry-radar-ci-target --query appId -o tsv)
az ad app credential reset --id "$TGT" --display-name er-test --years 1 --append >/dev/null # secret value discarded
az ad app permission add --id "$APP" --api "$GRAPH" --api-permissions "$ROLE=Role" 2>/dev/null || true
az ad app permission admin-consent --id "$APP"

cat <<OUT

Done. Set these repository variables (Settings > Secrets and variables > Actions > Variables, or gh):
  gh variable set AZURE_TEST_TENANT_ID -R $REPO -b $TENANT
  gh variable set AZURE_TEST_CLIENT_ID -R $REPO -b $APP
  gh variable set AZURE_TEST_VAULT     -R $REPO -b $KV
  gh variable set AZURE_TEST_GRAPH     -R $REPO -b 1
OUT
