# Terraform Cloud / HCP Terraform Integration

HCP Terraform (formerly Terraform Cloud) supports [OIDC workload identity](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/dynamic-provider-credentials/workload-identity-tokens), allowing TeamCity builds to authenticate to HCP Terraform without storing a long-lived API token.

## HCP Terraform setup

### 1. Create a workload identity provider

In HCP Terraform, go to **Settings → Workload Identity → New OIDC provider**.

- **Issuer URL:** your TeamCity root URL (e.g. `https://teamcity.example.com`)
- **Allowed audiences:** choose a string to use as the audience claim, e.g. `terraform.example.com`

Note the provider ID — you will need it when configuring the role binding.

### 2. Create a role binding

Add a role binding that maps claims from the TeamCity token to an HCP Terraform role:

- **Subject:** the build type external ID (e.g. `MyProject_InfraBuild`)
- **Role:** the HCP Terraform role to grant (e.g. **Workspace Write** for the relevant workspace)

The subject is matched against the `sub` claim in the token. Scope the binding to the minimum set of workspaces the build needs.

## Build feature configuration

In the OIDC Identity Token build feature:

- **Audience:** the audience string you configured in the HCP Terraform provider (e.g. `terraform.example.com`)
- **Algorithm:** RS256 (default)

## Using the token in build steps

Exchange the TeamCity JWT for an HCP Terraform API token using the OIDC token endpoint, then use that token to drive the `terraform` CLI:

```bash
# Exchange the TeamCity JWT for an HCP Terraform API token
HCP_TF_TOKEN=$(curl -s \
  --request POST \
  --header "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=%jwt.token%" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  --data-urlencode "audience=terraform.example.com" \
  "https://app.terraform.io/api/v2/oidc/token" \
  | jq -r '.access_token')

# Use the token with the Terraform CLI
export TFE_TOKEN="$HCP_TF_TOKEN"
terraform init
terraform apply -auto-approve
```

Or configure the [HCP Terraform CLI configuration](https://developer.hashicorp.com/terraform/cli/config/config-file) to use the token:

```bash
cat > ~/.terraform.d/credentials.tfrc.json <<EOF
{
  "credentials": {
    "app.terraform.io": {
      "token": "$HCP_TF_TOKEN"
    }
  }
}
EOF
```

## Dynamic provider credentials (alternative approach)

If your Terraform workspaces run in HCP Terraform and need credentials for AWS, Azure, or GCP, consider using [HCP Terraform Dynamic Provider Credentials](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/dynamic-provider-credentials) instead. In that model, HCP Terraform itself acts as the OIDC identity provider for your cloud resources — your TeamCity build just needs a workspace API token to trigger runs, and HCP Terraform handles cloud authentication internally during the plan/apply.

The OIDC-based approach described above is most useful when you need to trigger or manage HCP Terraform workspaces from a TeamCity build without storing a long-lived API token.
