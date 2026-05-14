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

In the trust policy, add conditions to restrict which builds can assume the role. Match on `build_type_internal_id` (or `project_internal_id`) rather than the external ID — internal IDs are immutable across project/build-type renames, so an admin rename can't silently change which builds can assume the role.

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
          "teamcity.example.com:build_type_internal_id": "bt42"
        }
      }
    }
  ]
}
```

Replace `teamcity.example.com` with your TeamCity hostname (without `https://`), and `bt42` with the build type's internal ID — visible in the build type URL (`.../buildType/bt42`) or the editor's "Build type ID" field. To trust any build type within a project, match on `project_internal_id` instead.

The token's `sub` claim is a composite identifier (`project:<project_internal_id>:build_type:<build_type_internal_id>[:branch:<branch>][:trigger_type:<trigger>]`) and can also be matched with `StringLike` and a wildcard, but matching the explicit `*_internal_id` claims is usually clearer.

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

The trust policy condition can use any claim included in the token (claims are always emitted regardless of the build feature's Subject scoping configuration). For example, to restrict to builds triggered from the `main` branch by a real user:

```json
"Condition": {
  "StringEquals": {
    "teamcity.example.com:aud": "sts.amazonaws.com",
    "teamcity.example.com:build_type_internal_id": "bt42",
    "teamcity.example.com:branch": "refs/heads/main",
    "teamcity.example.com:trigger_type": "user"
  }
}
```

Available claims include `build_type_internal_id`, `project_internal_id`, `build_type_external_id`, `project_external_id`, `branch`, and `trigger_type`. See the [Configuration Reference](configuration.md#standard-claims) for the full list.
