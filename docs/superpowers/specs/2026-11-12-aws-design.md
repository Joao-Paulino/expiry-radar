# AWS checker (M4)

Date: 2026-11-12 · Status: approved in conversation · Parent: [design spec](2026-11-10-expiry-radar-design.md) M4

Steps: **1. authentication + ACM + IAM server certificates** → 2. IAM access keys (credential report) → 3. Secrets Manager rotation. Same rules as Azure (M3): Go standard library only (no AWS SDK), read-only, never a secret value, every step reviewed independently; real-account validation at the end (Azure, AWS, GCP together).

## Authentication (no static keys, on purpose)
Exactly one `auth`:
- `instance_role` — detected: EKS Pod Identity / ECS (`AWS_CONTAINER_CREDENTIALS_FULL_URI` + `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, or `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` → `http://169.254.170.2`), else EC2 IMDSv2 (`PUT /latest/api/token`, then `/latest/meta-data/iam/security-credentials/<role>`). A full URI must point to loopback, `169.254.170.2` or `169.254.170.23` (as the AWS SDKs require). No proxy for these endpoints.
- `web_identity` — `AssumeRoleWithWebIdentity` with the token file (`token_file`/`role_arn` default to `AWS_WEB_IDENTITY_TOKEN_FILE`/`AWS_ROLE_ARN`, as EKS IRSA injects); token re-read on every refresh.
- `roles_anywhere` — IAM Roles Anywhere `CreateSession` signed with the X.509 key (`certificate_file` PEM with certificate + key, RSA or ECDSA; `trust_anchor_arn`, `profile_arn`, `role_arn`).
- Credentials cached until 5 min before `Expiration`.
- **Multi-account:** optional `assume_roles` (role ARNs, optional `external_id`): `sts:AssumeRole` from the base credentials into each account, `RoleSessionName=expiry-radar`. The base account is checked too unless `skip_base_account`.
- **Regions:** `regions` (required for ACM / Secrets Manager); IAM is global (signed for `us-east-1`).
- **SigV4** implemented in stdlib and tested against AWS's published signature test vectors.

## What is reported (step 1)
- **ACM** (`CertificateManager.ListCertificates`, JSON 1.1, paginated `NextToken`, `Includes.keyTypes` = all key types — without it ACM lists RSA-2048 only): kind `certificate`, name = domain, source `aws://acm/<account>/<region>/<certificate id>`, metadata `type` (AMAZON_ISSUED / IMPORTED / PRIVATE), `in_use`, `renewal_eligibility`, `status`, `account`, `region`. Imported certificates do not renew on their own: metadata says so. Certificates without `NotAfter` (pending validation) skipped.
- **IAM server certificates** (`ListServerCertificates`, Query API, paginated `Marker`): kind `certificate`, source `aws://iam/<account>/server-certificate/<name>`.
- No 30-day horizon for certificates (an expired one may still be served).

## Later steps (for the record)
- Step 2: access keys never expire; expiry = created/last rotated + `access_key_max_age_days` (default 90, CIS AWS Foundations). One credential report per account (`GenerateCredentialReport` + `GetCredentialReport`). Kind `access_key`.
- Step 3: Secrets Manager `ListSecrets` (no `GetSecretValue`): rotation enabled → `NextRotationDate`; disabled → optional `secret_max_age_days` from `LastChangedDate`.

## Errors and gone items
A failing account/region/service never hides the others. Empty dates are skipped, not errors (an error makes the run incomplete and turns off gone-detection for the whole checker). Service not enabled / region not opted-in → empty, not error.

## Permissions (read-only policy in README)
`acm:ListCertificates`, `iam:ListServerCertificates` (+ step 2 `iam:GenerateCredentialReport`, `iam:GetCredentialReport`; step 3 `secretsmanager:ListSecrets`); for multi-account `sts:AssumeRole` on the listed roles.

## Tests
Fake STS/IMDS/ECS/Roles Anywhere/ACM/IAM servers built from the API reference examples; SigV4 against the official test vectors; hostile container-credentials URI refused; optional CI job against a real account (GitHub OIDC → `AssumeRoleWithWebIdentity`) enabled by repository variables.
