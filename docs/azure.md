# Azure Integration

TeamCity can authenticate to Azure using [workload identity federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation). Builds exchange the `jwt.token` for an Azure access token without storing any client secrets in TeamCity.

## Azure setup

### 1. Create an app registration

In the Azure Portal, go to **Microsoft Entra ID → App registrations → New registration**. Note the **Application (client) ID** and **Directory (tenant) ID** — you will need both in your build steps.

### 1a. Alternative: user-assigned managed identity

If you prefer a managed identity over an app registration, federated credentials work the same way. Go to **Managed Identities → Create** (or use an existing user-assigned managed identity). Note the **Client ID** — this is used in place of an application client ID in your build steps. You can find the **Directory (tenant) ID** under **Microsoft Entra ID → Overview**.

Open the managed identity and go to **Federated credentials → Add credential**. Fill in the same fields as described in step 2 below. For role assignment (step 3), assign roles directly to the managed identity by name rather than to a service principal.

In your build steps, use the managed identity's Client ID with the same PowerShell command shown in the [Using the token in build steps](#using-the-token-in-build-steps) section below.

### 2. Add a federated identity credential

In the app registration, go to **Certificates & secrets → Federated credentials → Add credential**.

- **Federated credential scenario:** Other issuer
- **Issuer:** your TeamCity root URL (e.g. `https://teamcity.example.com`), or the value of **Override issuer URL** if one is configured under Administration → OIDC / JWT
- **Subject identifier:** the composite identifier emitted in the token's `sub` claim (e.g. `project:project7:build_type:bt42`)
- **Audience:** `api://AzureADTokenExchange`
- **Name:** a descriptive label (e.g. `teamcity-my-project-deploy`)

The subject identifier must match the `sub` claim in the token **exactly** — Azure federated credentials do not support wildcards. The plugin emits `sub` in the form `project:<project_internal_id>:build_type:<build_type_internal_id>[:branch:<branch>][:trigger_type:<trigger>]`; the optional segments are controlled by the **Subject scoping** checkboxes on the build feature.

For Azure, it is typically easiest to **uncheck `branch` and `trigger_type`** in the build feature so that `sub` is the minimal `project:<id>:build_type:<id>` form — one federated credential per build type, regardless of which branch built or how the build was triggered. The exact `sub` value is shown live in the build feature's "Resulting `sub` claim" preview; copy it directly into Azure's Subject identifier field.

The TeamCity internal IDs are visible in the build type URL (`.../buildType/bt42`) and are immutable across renames, so the federated credential keeps matching even if an admin renames the project or build type.

Add one federated credential per build type that needs access, or use a separate app registration per team/environment.

### 3. Assign Azure roles

Go to the resource (subscription, resource group, storage account, etc.) and assign the appropriate role (e.g. **Contributor**, **Storage Blob Data Contributor**) to the app registration or managed identity.

## Build feature configuration

In the OIDC Identity Token build feature:

- **Audience:** `api://AzureADTokenExchange`
- **Algorithm:** RS256 (default)

## Using the token in build steps

Log in using the Azure PowerShell module (`Az.Accounts`):

```powershell
Connect-AzAccount `
  -ServicePrincipal `
  -ApplicationId "<application-client-id>" `
  -TenantId "<directory-tenant-id>" `
  -FederatedToken "%jwt.token%"
```

All subsequent `Az` commands in the same step will use that identity.

> **Prerequisite:** The `Az.Accounts` module must be available on the agent. The simplest approach is to run the build step in Microsoft's Azure PowerShell container image — set the runner to **Docker** with image `mcr.microsoft.com/azure-powershell:latest`. Alternatively, install once on the agent with `Install-Module -Name Az.Accounts -Scope CurrentUser -Force -AllowClobber`.

> **Note:** `az login --federated-token` is not yet a publicly supported Azure CLI feature ([azure-cli#24756](https://github.com/Azure/azure-cli/issues/24756)) and fails when the token expires mid-build. Use the PowerShell module until official CLI support ships.

## Restricting access further

The subject identifier in the federated credential is matched against the `sub` claim. You can scope access more narrowly by:

- **Including more dimensions in `sub`** — tick `branch` and/or `trigger_type` in the build feature's Subject scoping section. A federated credential with subject `project:project7:build_type:bt42:branch:refs/heads/main:trigger_type:user` only matches builds of that specific build type on `main` triggered by a user. Note: because Azure has no wildcards, you'd need one federated credential per concrete `(branch, trigger_type)` combination you want to allow.
- **Multiple app registrations** — create separate app registrations for different environments (staging vs. production), each with its own role assignments and federated credential(s).
- **Azure ABAC on resources** — the token always carries the `branch` claim as a flat key/value pair. [Azure attribute-based access control](https://learn.microsoft.com/en-us/azure/role-based-access-control/conditions-overview) conditions on storage resources can use it for branch-level restrictions without changing the federated credential. This is typically simpler than maintaining a credential per branch.
