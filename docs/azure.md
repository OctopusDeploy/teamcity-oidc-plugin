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
- **Issuer:** your TeamCity root URL (e.g. `https://teamcity.example.com`)
- **Subject identifier:** the build type external ID (e.g. `MyProject_DeployBuild`)
- **Audience:** `api://AzureADTokenExchange`
- **Name:** a descriptive label (e.g. `teamcity-my-project-deploy`)

The subject identifier must match the `sub` claim in the token exactly. Add one federated credential per build type that needs access, or use a separate app registration per team/environment.

### 3. Assign Azure roles

Go to the resource (subscription, resource group, storage account, etc.) and assign the appropriate role (e.g. **Contributor**, **Storage Blob Data Contributor**) to the app registration or managed identity.

## Build feature configuration

In the OIDC Identity Token build feature:

- **Audience:** `api://AzureADTokenExchange`
- **Algorithm:** RS256 (default)

## Using the token in build steps

Log in using the Azure PowerShell module:

```powershell
Connect-AzAccount `
  -ServicePrincipal `
  -ApplicationId "<application-client-id>" `
  -TenantId "<directory-tenant-id>" `
  -FederatedToken "%jwt.token%"
```

All subsequent `Az` commands in the same step will use that identity.

> **Note:** `az login --federated-token` is not yet a publicly supported Azure CLI feature ([azure-cli#24756](https://github.com/Azure/azure-cli/issues/24756)) and fails when the token expires mid-build. Use the PowerShell module until official CLI support ships.

## Restricting access further

The subject identifier in the federated credential is matched against the `sub` claim. You can scope access more narrowly by creating separate app registrations (and assigning different roles) for different build types or environments.

If you include the `branch` claim in the token, you can use [Azure attribute-based access control (ABAC)](https://learn.microsoft.com/en-us/azure/role-based-access-control/conditions-overview) conditions on storage resources to enforce branch-level restrictions. For most use cases, separate federated credentials per environment (staging vs. production) is simpler.
