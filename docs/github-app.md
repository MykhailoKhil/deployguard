# GitHub App configuration

DeployGuard uses a GitHub App. It must not use a personal access token, a
long-lived installation token, or AWS credentials.

The authenticated web workflow also requires GitHub App user authorization
(OAuth) credentials. Set `DEPLOYGUARD_GITHUB_OAUTH_CLIENT_ID`,
`DEPLOYGUARD_GITHUB_OAUTH_CLIENT_SECRET`, `DEPLOYGUARD_GITHUB_OAUTH_REDIRECT_URL`,
and the browser-facing HTTPS `DEPLOYGUARD_PUBLIC_ORIGIN`. The callback URL must
be registered in the GitHub App's user authorization callback settings. The
service keeps OAuth access tokens only in short-lived in-memory sessions.

## Quick setup

The fastest way to create the App is the setup tool. You need a public HTTPS address for DeployGuard first.

1. Run `go run ./cmd/github-app-setup -origin https://<your-public-host>`.
2. Open the local address it prints, in a browser signed in to GitHub, and click **Create GitHub App**.
3. The tool writes the credentials to `.env.github` (mode `0600`) and prints the link to install the App. Install it on **selected repositories** only.
4. Start DeployGuard with `set -a && source .env.github && set +a && go run ./cmd/deployguard`.

The tool requests exactly the permissions and events listed under "Events and permissions" below, makes the App private, and registers the webhook and callback URLs from `-origin`. If your address changes (for example a temporary tunnel), edit the Webhook URL and Callback URL in the App's settings and update `DEPLOYGUARD_PUBLIC_ORIGIN` and `DEPLOYGUARD_GITHUB_OAUTH_REDIRECT_URL`. To create the App by hand instead, use the values in the sections below.

## Required secrets and configuration

- `DEPLOYGUARD_GITHUB_APP_ID`: the numeric App ID.
- `DEPLOYGUARD_GITHUB_PRIVATE_KEY_PEM`: the App's RSA private key, provided at
  runtime through a secret manager or environment injection.
- `DEPLOYGUARD_GITHUB_WEBHOOK_SECRET`: optional, at least 20 random characters
  (for example `openssl rand -hex 32`); use the same value in the App's webhook
  settings. When set, the server mounts `POST /webhooks/github`, verifies every
  delivery's signature, and publishes Check Runs. It also requires
  `DEPLOYGUARD_PLAN_WORKFLOW_FILENAME` and `DEPLOYGUARD_PLAN_ARTIFACT_NAME`,
  because the plan is fetched from that workflow's artifact. Set the webhook URL
  to `<DEPLOYGUARD_PUBLIC_ORIGIN>/webhooks/github`.
- `DEPLOYGUARD_GITHUB_API_BASE_URL`: optional GitHub API base URL. Defaults to
  `https://api.github.com`; set it for GitHub Enterprise Server.
- `DEPLOYGUARD_GITHUB_WEB_BASE_URL`: optional GitHub web base URL. Defaults to
  `https://github.com`; set it to the GitHub Enterprise Server web host when
  applicable.
- `DEPLOYGUARD_LISTEN_ADDRESS`: optional listen address; defaults to `:8080`. The
  service speaks plain HTTP: run it behind a TLS-terminating reverse proxy.
- `DEPLOYGUARD_TRUSTED_PROXY_HEADER`: optional header name (for example
  `X-Forwarded-For`) that your own proxy sets to the client IP. It is used for
  rate limiting only, and the right-most value is used. Leave it unset unless a
  proxy you control overwrites the header, otherwise clients can forge it.
- `DEPLOYGUARD_SESSION_TTL`: optional session duration from 5 minutes to 24
  hours; defaults to 30 minutes.
- `DEPLOYGUARD_PLAN_WORKFLOW_FILENAME` and
  `DEPLOYGUARD_PLAN_ARTIFACT_NAME`: optional pair enabling Actions artifact
  retrieval. `DEPLOYGUARD_PLAN_JSON_FILENAME` defaults to `tfplan.json`.

Do not write the private key, webhook secret, App JWT, installation token,
webhook body, or Terraform plan content to logs. The service keeps App keys in
memory and creates installation tokens only when repository-scoped API work is
needed.

## Events and permissions

Subscribe to the **Pull request** and **Workflow run** webhook events. For
pull requests the endpoint accepts only `opened`, `reopened`, and `synchronize`
actions; for workflow runs only a `completed`, successful run triggered by a
pull request from the same repository. Every delivery is signature-checked
first. `ping` is answered 200, and everything else (other actions, other
events such as `issue_comment`) is acknowledged with 202 and ignored, so GitHub
does not mark it as a failed delivery. A repeated delivery ID is not processed
twice. A pull request event alone publishes nothing when the plan artifact is
not ready yet: the plan workflow's completion triggers the analysis.

Start with these repository permissions:

| Permission | Access | Purpose |
| --- | --- | --- |
| Metadata | Read | GitHub App repository identity is always available. |
| Pull requests | Read | Read the pull-request commit context when required. |
| Checks | Write | Publish the DeployGuard Check Run. |
| Actions | Read | Download the plan artifact of the finished workflow run (required for Check Runs). |
| Pull requests | Write | Only if `DEPLOYGUARD_PR_COMMENTS=true` (one comment per pull request). Off by default. |
| Attestations | Read | Only if plan provenance checking is enabled (`DEPLOYGUARD_PROVENANCE_TRUSTED_ROOT`). Off by default. |

Request Actions read access only when Actions plan-artifact retrieval is
enabled. Request Pull requests write only if you turn on pull request comments,
and Attestations read only if you turn on plan provenance. Do not grant
administration, contents write, issues write, or any AWS permission.

## Request flow

1. Apply the webhook body limit and source rate limit.
2. Verify `X-Hub-Signature-256` over the exact raw body with constant-time
   comparison.
3. Parse the pull-request event fields needed for analysis.
4. Authenticate as the GitHub App with a short-lived JWT and call GitHub's
   repository-installation endpoint.
5. Require the returned installation ID to equal the webhook installation ID.
6. Mint an installation token only for subsequent repository-scoped work.

This confirms that a signed event is associated with the App installation that
can access the named repository. It prevents tenant selection from being driven
solely by unverified payload fields.

## Interactive Terraform plan review

The service provides a browser flow at `/`: sign in with GitHub, choose an
App-installed repository and open pull request, then upload an existing plan
JSON file. Convert a locally generated binary plan first with
`terraform show -json tfplan > tfplan.json`; DeployGuard never runs Terraform.
Uploads are limited to 10 MiB and processed in memory. An upload is associated
with the current selected pull-request head, but is not cryptographically
attested as having been generated from that commit. Review the plan source
before relying on the result.

Actions retrieval is optional. Configure the workflow filename, artifact name,
and JSON filename to match `.github/workflows/deployguard-plan.yml`. The sample
workflow is limited to same-repository pull requests, uses the `pull_request`
trigger (never `pull_request_target`), and uploads only the JSON file for one
day. Terraform configuration and provider plugins execute in the repository's
Actions runner and can access any credentials granted there. Protect the
`deployguard-plan` GitHub Actions environment, require approval where
appropriate, and supply only narrow, short-lived, read-only cloud credentials.
Never expose production credentials automatically to untrusted PR changes.
The initial workflow intentionally skips fork pull requests.

**A pull request author can change the workflow.** The workflow runs from the
pull request head, so anyone who can open a same-repository pull request can edit
it to upload a hand-written `tfplan.json`. DeployGuard only accepts runs of the
configured workflow file that succeeded for the exact head commit, in the same
repository, for that pull request, and it labels Actions plans as unattested for
this reason. To make the result trustworthy, protect `.github/workflows/` with
CODEOWNERS and a branch ruleset that requires owner review, or generate plans
from a trusted default-branch workflow. DeployGuard cannot verify that a plan
matches what Terraform would really do.

The sample workflow runs the plan JSON through `jq` before upload so only the
fields DeployGuard reads are kept and every value Terraform marks as sensitive
is replaced by `null`. This reduces, but does not remove, exposure: Terraform
plan JSON can contain secrets that are not marked sensitive.
The GitHub Actions artifact remains available for its
configured retention period; restrict artifact access, keep retention short,
and do not treat DeployGuard's in-memory analysis as protection for the source
artifact.
