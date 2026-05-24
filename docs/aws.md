# AWS Integration

TeamCity can authenticate to AWS using [IAM Roles Anywhere / OIDC federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html). Builds exchange the `jwt.token` for short-lived AWS credentials without storing any AWS secrets in TeamCity.

## AWS setup

### 1. Create an IAM OIDC identity provider

In the AWS Console, go to **IAM → Identity providers → Add provider**.

- **Provider type:** OpenID Connect
- **Provider URL:** your TeamCity root URL (e.g. `https://teamcity.example.com`), or the value of **Override issuer URL** if one is configured under Administration → OIDC / JWT
- **Audience:** `sts.amazonaws.com`

Click **Get thumbprint**, then **Add provider**.

### 2. Create an IAM role

Create a role with a **Web identity** trusted entity. Select the OIDC provider you just created.

In the trust policy, add conditions to restrict which builds can assume the role. For self-hosted OIDC providers AWS only exposes the standard OIDC claims (`sub`, `aud`, `amr`, `oaud`, `email`) as IAM condition keys — the plugin's custom claims (`build_type_internal_id`, `project_internal_id`, `branch`, `trigger_type`, etc.) are emitted into the token but are **not** available in trust policies. See [Available keys for AWS OIDC federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html#condition-keys-wif) for the authoritative list. Restrict access by matching on `sub`, which the plugin composes as a colon-separated identifier built from the build's rename-stable internal IDs: `project:<project_internal_id>:build_type:<build_type_internal_id>[:branch:<branch>][:trigger_type:<trigger>]`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/teamcity.example.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "teamcity.example.com:aud": "sts.amazonaws.com",
          "teamcity.example.com:sub": "project:MyApp_Backend:build_type:bt42"
        }
      }
    }
  ]
}
```

Replace `teamcity.example.com` with your TeamCity hostname (without `https://`), and replace `MyApp_Backend` and `bt42` with your project and build-type internal IDs. The build type's internal ID is visible in its URL (`.../buildType/bt42`) or in the editor's "Build type ID" field; the project's internal ID is visible similarly under `.../project/<id>`. Internal IDs are immutable across renames, so an admin rename can't silently change which builds can assume the role. To trust any build type within a project, use `StringLike` with a wildcard value of `"project:MyApp_Backend:build_type:*"`.

Attach the required permissions policies to the role.

## Build feature configuration

In the OIDC Identity Token build feature:

- **Audience:** `sts.amazonaws.com`
- **Algorithm:** RS256 (default)

## Using the token in build steps

Write the token to a file, then set the standard AWS environment variables so the SDK and CLI pick it up automatically:

```bash
# Write the token to a temporary file
echo "%jwt.token%" > /tmp/aws-web-identity-token

# Set AWS environment variables — the SDK/CLI reads these automatically
export AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/aws-web-identity-token
export AWS_ROLE_ARN=arn:aws:iam::123456789012:role/my-teamcity-role
export AWS_ROLE_SESSION_NAME=teamcity-build-%build.number%

# All subsequent AWS CLI / SDK calls now use the assumed role
aws sts get-caller-identity
```

The SDK reads from the token file each time it needs credentials, so the token only needs to be valid at the point each request is made, not for the entire build. Set the token TTL to comfortably exceed the time from build start to the first AWS credential request.

Alternatively, assume the role explicitly and export the resulting credentials:

```bash
CREDS=$(aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::123456789012:role/my-teamcity-role \
  --role-session-name teamcity-build-%build.number% \
  --web-identity-token "%jwt.token%" \
  --query "Credentials" \
  --output json)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)
```

With this approach the token must still be valid at the point `assume-role-with-web-identity` runs, so ensure the TTL is long enough if this step runs late in a long build.

## Restricting access further

To restrict by branch or trigger type, opt in to those dimensions in the build feature's **Subject scoping** configuration. The plugin will then append them to the `sub` claim, which lets you match them exactly in the trust policy. For example, to restrict to builds triggered from the `main` branch by a real user (with both `branch` and `trigger_type` enabled in Subject scoping):

```json
"Condition": {
  "StringEquals": {
    "teamcity.example.com:aud": "sts.amazonaws.com",
    "teamcity.example.com:sub": "project:MyApp_Backend:build_type:bt42:branch:refs/heads/main:trigger_type:user"
  }
}
```

The dimensions are appended to `sub` in a fixed order — `project`, `build_type`, `branch`, `trigger_type` — so only the trailing dimensions are optional. See the [Subject claim](configuration.md#subject-claim) section of the Configuration Reference for the full grammar and the values each dimension can take (e.g. `trigger_type` is one of `user`, `snapshotDependency`, `vcsTrigger`, `schedulingTrigger`, etc.). To match a subset of values (e.g. any branch under `refs/heads/`), use `StringLike` with `*` wildcards instead of `StringEquals`.
