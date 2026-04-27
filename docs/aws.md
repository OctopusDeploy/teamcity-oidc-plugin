# AWS Integration

TeamCity can authenticate to AWS using [IAM Roles Anywhere / OIDC federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html). Builds exchange the `jwt.token` for short-lived AWS credentials without storing any AWS secrets in TeamCity.

## AWS setup

### 1. Create an IAM OIDC identity provider

In the AWS Console, go to **IAM → Identity providers → Add provider**.

- **Provider type:** OpenID Connect
- **Provider URL:** your TeamCity root URL (e.g. `https://teamcity.example.com`)
- **Audience:** `sts.amazonaws.com`

Click **Get thumbprint**, then **Add provider**.

### 2. Create an IAM role

Create a role with a **Web identity** trusted entity. Select the OIDC provider you just created.

In the trust policy, add conditions to restrict which builds can assume the role:

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
          "teamcity.example.com:sub": "MyProject_DeployBuild"
        }
      }
    }
  ]
}
```

Replace `teamcity.example.com` with your TeamCity hostname (without `https://`), and `MyProject_DeployBuild` with the build type external ID. You can use `StringLike` with a wildcard (`MyProject_*`) to match multiple build types.

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

## Restricting access further

The trust policy condition can use any claim included in the token. For example, to restrict to builds triggered from the `main` branch:

```json
"Condition": {
  "StringEquals": {
    "teamcity.example.com:sub": "MyProject_DeployBuild",
    "teamcity.example.com:branch": "main"
  }
}
```

Make sure **branch** is included in the build feature's claims configuration.
