<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/wordmark-dark.svg">
    <img src="assets/brand/wordmark-light.svg" alt="DeployGuard" width="390">
  </picture>
</p>

# DeployGuard

**Know the risk before infrastructure changes go live.**

<p align="center"><img src="assets/brand/social-banner.svg" alt="DeployGuard: know the risk before infrastructure changes go live." width="100%"></p>

DeployGuard reads a Terraform plan (as JSON) and tells you how risky it is to apply. It reports:

- a risk score from 0 to 100 and a level: `LOW`, `MEDIUM`, `HIGH` or `CRITICAL`;
- a recommendation: `SAFE`, `REVIEW` or `BLOCK`;
- a list of findings, each with a concrete "Next step".

**Deterministic rules decide the verdict, not AI.** An optional AI summary only explains the findings and never changes them.

DeployGuard does not run Terraform, apply changes, scan live cloud accounts, or need AWS credentials.

The rules cover AWS: resource replacement, deleting production resources and CloudWatch alarms, more permissive security groups, disabled encryption, publicly accessible RDS, large or critical changes, capacity increases, and lost monitoring. This is not a complete security or cost assessment.

It runs in two modes:

| Mode | Use it to | Needs |
| --- | --- | --- |
| **Local** | Upload a plan in the browser and read the verdict | Go only |
| **GitHub** | Post a `DeployGuard` check on pull requests automatically | A GitHub App and a public HTTPS address |

> **Which mode do I need?**
> - **Just trying it, or checking plans by hand?** Use **local mode**. It needs only Go and takes five minutes. Start here.
> - **Want a check on every pull request?** Add **GitHub mode** later, once local mode works. It needs a GitHub App and a public HTTPS address.
> - Not sure? Local mode.

### Terms used in this README

| Term | Meaning |
| --- | --- |
| **Terraform plan** | The preview Terraform makes of what it would change. DeployGuard reads it; it never applies it. |
| **Plan JSON** | The plan converted to JSON with `terraform show -json`. This is the file you upload (`tfplan.json`). |
| **Finding** | One risk the rules found, with a severity and a "Next step". |
| **Verdict** | The overall result: score, level and `SAFE` / `REVIEW` / `BLOCK`. |
| **GitHub App** | A GitHub integration you register once. It lets DeployGuard receive pull request events and post checks. |
| **Check Run** | The status line GitHub shows on a pull request (like a CI result). DeployGuard posts one named `DeployGuard`. |
| **Workflow artifact** | A file a GitHub Actions run saves. Your plan workflow saves `tfplan.json` as one. |

## Requirements

| Software | Version | Needed for |
| --- | --- | --- |
| [Go](https://go.dev/dl/) | 1.26 or newer. `go.mod` also names the patched toolchain go1.26.11, which the `go` command downloads automatically | running and testing |
| [Terraform](https://developer.hashicorp.com/terraform/install) | any recent version; tested with 1.14.9 | producing your own plan |
| [Node.js](https://nodejs.org/) | tested with 26.3 (no older version tried) | two browser-script test files only |
| [Docker](https://docs.docker.com/get-docker/) | tested with 29.4 | container run only |

Tested only on macOS 26.6 (Apple Silicon). The commands need just Go and a POSIX shell, so Linux should work, but it and Windows are untested. There is no database and no third-party Go dependency: the project builds from the Go standard library alone.

## Install and first run (5 minutes)

Prefer not to install Go? Prebuilt binaries are attached to tagged releases (see "Prebuilt binaries" below). Otherwise:

**1. Get the code.**

```bash
git clone https://github.com/MykhailoKhil/deployguard.git DeployGuard
cd DeployGuard
```

**2. Start it.** No environment variables and no dependency download are needed.

```bash
go run ./cmd/deployguard
```

The first run compiles the project, so wait a few seconds. The terminal prints a JSON line containing `"mode":"local"` and `"address":"127.0.0.1:8080"`:

```
{"time":"…","level":"INFO","msg":"DeployGuard listening","mode":"local","address":"127.0.0.1:8080","ai_enabled":false,"open":"http://127.0.0.1:8080"}
```

The `open` field is the address to visit. The terminal stays busy; that is normal. Press `Ctrl+C` to stop.

If you see `127.0.0.1:8080 is already in use`, another program has the port. Start on a different one:

```bash
DEPLOYGUARD_LISTEN_ADDRESS=127.0.0.1:8090 go run ./cmd/deployguard
```

then open the address from the `open` field.

**3. Open** <http://127.0.0.1:8080>. Use `127.0.0.1`, not `localhost` (see Troubleshooting).

**4. Try the bundled example.** Choose `examples/tfplan.json` from this repository and click **Analyze plan**.

Expected: recommendation **BLOCK**, score **100/100**, level CRITICAL, six findings, including "RDS instance will become publicly accessible", "CloudWatch alarm will be deleted" and "Security group is becoming publicly accessible". Each finding has a "Next step" line.

If you see that, the installation works.

> Local mode has no login: anyone using this computer can open the page. It listens on `127.0.0.1` only. Do not expose it through a tunnel or proxy.

## Prebuilt binaries

Pushing a tag such as `v0.1.0` runs [`.github/workflows/release.yml`](.github/workflows/release.yml), which tests the code, builds binaries for Linux (amd64, arm64), macOS (amd64, arm64) and Windows (amd64), and attaches them with a `SHA256SUMS` file to a GitHub release. **No release has been published yet**, and the workflow has not run on GitHub; the five targets were cross-compiled locally to confirm they build.

With a binary you skip steps 1 and 2 above:

```bash
chmod +x deployguard-darwin-arm64     # name depends on your system
./deployguard-darwin-arm64
```

Verify the download with `shasum -a 256 -c SHA256SUMS` (macOS) or `sha256sum -c SHA256SUMS` (Linux). Binaries are not code-signed, so macOS and Windows may warn on first run.

## Check your own Terraform plan

In your Terraform directory:

```bash
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
```

Upload **`tfplan.json`**, not the binary `tfplan`. The size limit is 10 MiB.

A plan can contain secrets. Create it in your own trusted environment and do not share it.

## Optional: AI summary

The AI summary is a short note under the verdict: one sentence about the changes and up to three "Next step" lines. It is labelled "generated, not authoritative" and is off by default. You choose the provider, so you are not tied to one vendor.

| `DEPLOYGUARD_AI_PROVIDER` | Service | Default address (`DEPLOYGUARD_AI_BASE_URL`) | Example model |
| --- | --- | --- | --- |
| `anthropic` (default) | Anthropic Claude, or any Anthropic Messages-compatible gateway such as OmniRoute | `https://api.anthropic.com` | `claude-sonnet-5-5` |
| `openai` | OpenAI, or any OpenAI-compatible server (OpenRouter, Ollama, vLLM, LM Studio) | `https://api.openai.com` | `gpt-4o-mini` |
| `gemini` | Google Gemini | `https://generativelanguage.googleapis.com` | `gemini-2.0-flash` |
| `mistral` | Mistral | `https://api.mistral.ai` | `mistral-small-latest` |

Model names change often; check your provider's current list. The examples are illustrations, not recommendations.

AI turns on when `DEPLOYGUARD_AI_PROVIDER` or `DEPLOYGUARD_AI_BASE_URL` is set. Then the API key and model are required. Examples (use your own key and model):

```bash
# OpenAI (the address defaults to https://api.openai.com)
export DEPLOYGUARD_AI_PROVIDER=openai
export DEPLOYGUARD_AI_API_KEY=<your key>
export DEPLOYGUARD_AI_MODEL=gpt-4o-mini
go run ./cmd/deployguard
```

```bash
# A local OpenAI-compatible server such as Ollama
export DEPLOYGUARD_AI_PROVIDER=openai
export DEPLOYGUARD_AI_BASE_URL=http://127.0.0.1:11434   # no /v1 suffix
export DEPLOYGUARD_AI_API_KEY=unused-but-required
export DEPLOYGUARD_AI_MODEL=llama3.1
```

```bash
# Anthropic through a gateway such as OmniRoute (the original setup; the provider defaults to anthropic)
export DEPLOYGUARD_AI_BASE_URL=http://127.0.0.1:20128   # no /v1 suffix
export DEPLOYGUARD_AI_API_KEY=<your key>
export DEPLOYGUARD_AI_MODEL=<model name>
```

To switch providers, change `DEPLOYGUARD_AI_PROVIDER` (and the key and model to match) and restart. Existing setups that only set `DEPLOYGUARD_AI_BASE_URL` keep working unchanged.

How it behaves:

- The AI receives only rule IDs, severities, summaries, remediation text and resource addresses. The plan and attribute values are never sent.
- If the service takes longer than 15 seconds or fails, the page is shown without the summary.
- The key is only sent over HTTPS, or to `localhost`/`127.0.0.1`. For Gemini it travels in a header, never in the URL.
- `ANTHROPIC_*` variables are deliberately ignored, so settings of other tools cannot enable it by accident.

## Verdict history

Both modes have a **History** page (the "History" link in the header, or `/history`) that lists past verdicts, newest first: when, what was analyzed, recommendation, level, score, and the rules that fired. **Only the verdict is kept, never the plan, attribute values or resource names.**

- **Local mode** records every plan you upload on the home page, in a file: `history.jsonl` in your user config folder (on macOS `~/Library/Application Support/deployguard/`, on Linux `~/.config/deployguard/`). Each entry has the verdict, the rule IDs and a fingerprint (SHA-256) of the plan, so you can tell that two uploads were the same plan. The file is private to you (mode `0600`, folder `0700`) and keeps the newest 500 entries. Set `DEPLOYGUARD_HISTORY_FILE` to an absolute path to move it, or to `off` to keep no history. If the file cannot be written, uploads still work and the server logs a warning.
- **GitHub mode** needs the PostgreSQL database (next section). It records verdicts from webhook analyses **and** from reviews started on the site. The page shows only verdicts for repositories the signed-in user can access on GitHub: other repositories of the same installation, and other installations, are never read. Without `DEPLOYGUARD_DATABASE_URL` the page says history is off. Analyzing the same commit again replaces its row (one verdict per commit).

## Optional: verdict history (PostgreSQL, GitHub mode)

DeployGuard can remember each verdict per GitHub App installation (the "tenant"). It is off by default and only available in GitHub mode. Set a connection URL and restart:

```bash
export DEPLOYGUARD_DATABASE_URL='postgres://<user>:<password>@<host>:5432/<database>'
```

What is stored: the repository, pull request, commit, recommendation, level, score, and the rule IDs and severities that fired. There is **one verdict per commit of a pull request**: analyzing the same commit again (a workflow rerun, a redelivered webhook) replaces its row instead of adding a duplicate. **Plans, attribute values, resource names and AI text are never stored.** Verdicts older than `DEPLOYGUARD_RETENTION_DAYS` (default 90) are deleted automatically, now and every six hours.

How tenants are kept apart: every query filters by installation, and PostgreSQL row-level security (forced, so it applies even to the table owner) makes the database itself refuse cross-tenant reads and writes. Because superusers bypass row-level security, DeployGuard **refuses to start** if the database role is a superuser or has `BYPASSRLS`. Use a dedicated role, for example:

```sql
CREATE ROLE deployguard LOGIN PASSWORD '<a strong password>' NOSUPERUSER NOBYPASSRLS;
CREATE DATABASE deployguard OWNER deployguard;
```

A database on another machine must use TLS: put `?sslmode=require` (or `verify-full`) in the URL, or startup fails. Tables are created automatically on first start by embedded migrations.

## Settings in a `.env` file

Instead of `export`, put the variables in a `.env` file (git ignores it):

```bash
cp .env.example .env
```

Edit `.env`, then start with:

```bash
set -a && source .env && set +a && go run ./cmd/deployguard
```

`.env.example` documents every variable. Keep its GitHub lines commented out if you want local mode.

## Tests

From the repository root:

```bash
go vet ./...
go test -race ./...
```

Expected: `go vet` prints nothing, and `go test` prints one `ok` line per package (eleven) and no `FAIL`:

```
ok  	github.com/deployguard/deployguard/cmd/deployguard
ok  	github.com/deployguard/deployguard/cmd/github-app-setup
ok  	github.com/deployguard/deployguard/internal/ai
ok  	github.com/deployguard/deployguard/internal/domain
ok  	github.com/deployguard/deployguard/internal/github
ok  	github.com/deployguard/deployguard/internal/plan
ok  	github.com/deployguard/deployguard/internal/provenance
ok  	github.com/deployguard/deployguard/internal/review
ok  	github.com/deployguard/deployguard/internal/risk
ok  	github.com/deployguard/deployguard/internal/store
ok  	github.com/deployguard/deployguard/internal/web
```

If Node.js is installed, also run the browser-script tests:

```bash
node --test internal/web/theme.test.js internal/web/busy.test.js
```

Expected: `tests 5`, `pass 5`, `fail 0`.

The PostgreSQL integration tests are skipped unless `DEPLOYGUARD_TEST_POSTGRES_URL` points at a throwaway server (a superuser URL; each test creates its own database and a restricted role). Example with Docker:

```bash
docker run -d --name dg-pg -e POSTGRES_PASSWORD=postgres -p 127.0.0.1:55432:5432 postgres:17-alpine
export DEPLOYGUARD_TEST_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:55432/postgres
go test -race ./internal/store
```

The other tests need no internet, tokens or GitHub: GitHub is replaced by fakes. [`.github/workflows/test.yml`](.github/workflows/test.yml) runs the same checks on every push and pull request.

## GitHub mode: checks on pull requests

In this mode DeployGuard accepts signed GitHub webhooks. When the workflow that builds your Terraform plan finishes successfully for a pull request, DeployGuard downloads its artifact, analyzes it, and publishes **one** `DeployGuard` Check Run on the commit: `SAFE` is success, `REVIEW` is neutral, `BLOCK` is failure. A repeated event updates the same run. Fork pull requests are skipped.

**Optional pull request comment.** Set `DEPLOYGUARD_PR_COMMENTS=true` to also keep one comment on the pull request with the same content as the Check Run. How it behaves:

- It names the commit it describes (`Commit abc1234`).
- A verdict that is the same or better is **edited in place**, which sends no notification.
- A verdict that gets **worse** (for example SAFE to BLOCK) is posted as a **new comment**, because GitHub notifies people about new comments but not edits. The previous DeployGuard comment is deleted, so one remains.
- When a commit has no verdict (plan workflow finished but the artifact is missing or unreadable), the comment says so instead of keeping the previous commit's verdict.
- If the pull request has moved on to a newer commit by the time an analysis finishes, the comment is left alone.
- Text that comes from the plan or the AI is stripped of automatic links and cross-references (an invisible character is inserted where a link would start), so a hostile resource name cannot make the bot post a clickable link.
- A pull request thread is searched in full up to 1000 comments; in a longer one the oldest and newest 500 are searched, and a DeployGuard comment buried in the middle is not found (a new one is posted).
- If GitHub refuses to write the comment, the log says `permission missing` and what to change.
- DeployGuard only ever edits or deletes comments its own App wrote (identified by the App and its bot user), and it removes duplicate DeployGuard comments if it finds any. Several DeployGuard instances at once can briefly leave two comments; the next update removes the extra one.

 It needs the GitHub App permission **Pull requests: write**, which breaks the default read-only setup, so it is off by default. Create the App with `go run ./cmd/github-app-setup -pr-comments ...` (or raise the permission in the App's settings and accept it on the installation). If the permission is missing, the Check Run is still published and a warning is logged.

You need:

1. **A GitHub App** with Checks (write); Actions, Pull requests and Metadata (read); and the Pull request and Workflow run events. The setup tool below creates it for you. Permissions and security notes: [docs/github-app.md](docs/github-app.md).
2. **A public HTTPS address** for DeployGuard: sign-in and webhooks do not work on `http://127.0.0.1`. For an experiment a temporary tunnel such as [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) is enough. Its address changes on every start, and then the Webhook URL and Callback URL in the GitHub App must be updated. Permanent hosting is not documented yet.
3. **A workflow that builds the plan.** Sample: [.github/workflows/deployguard-plan.yml](.github/workflows/deployguard-plan.yml). It uploads an artifact containing `tfplan.json` with every value Terraform marks sensitive blanked out (the file is a downloadable artifact), pins its actions to commit SHAs, and does not persist checkout credentials. Read the security notes at its top first: it runs `terraform plan` on pull request code, so it belongs in a protected environment named `deployguard-plan` (required reviewers) that exposes only short-lived, read-only cloud credentials. Environments on private repositories need a GitHub plan that supports them; without one, remove the `environment:` line and keep the credentials read-only. The redaction was checked to give the same DeployGuard verdict as the raw plan.
4. **The environment variables** below. The six required ones must be set together, otherwise the server refuses to start and says what is missing.

### Create the GitHub App with the setup tool

Once you have a public HTTPS address (step 2), run:

```bash
go run ./cmd/github-app-setup -origin https://<your-public-host>
```

It prints a local address. Open it in a browser signed in to GitHub, confirm the App on GitHub's page, and the tool saves the credentials to `.env.github` (permissions `0600`; secrets are never printed). Then it prints the link to install the App on a repository. Choose "Only select repositories" there. Options: `-name` (App name, must be unique on GitHub), `-out`, `-workflow`, `-artifact`, `-force` (overwrite an existing file). `go run ./cmd/github-app-setup -h` lists them.

The tool is covered by tests with a fake GitHub, but creating a real App needs your confirmation on GitHub, so the full flow is only as tested as the manual run done during development.

Start with the generated file:

```bash
set -a && source .env.github && set +a && go run ./cmd/deployguard
```

Or, if you filled in `.env` by hand instead:

```bash
set -a && source .env && set +a && go run ./cmd/deployguard
```

The log should show `"mode":"github"` and `"webhook_enabled":true`. Quick check: `GET /healthz` returns `ok`, and an unsigned `POST /webhooks/github` returns `401`.

About the webhook endpoint (full details in [docs/api/openapi.yaml](docs/api/openapi.yaml)):

- Every delivery is signature-checked first. GitHub's initial `ping` is answered `200`.
- Events DeployGuard does not use (for example `issue_comment`), and pull request actions such as `closed` or `labeled`, are acknowledged with `202` and ignored, so GitHub does not show them as failed deliveries.
- A redelivery of the same `X-GitHub-Delivery` ID is acknowledged and not processed again. A delivery that failed with `5xx` can be redelivered and is retried.
- At startup DeployGuard checks the GitHub App's configured permissions against the features you enabled and logs one warning per missing permission, with what to change. It never stops the server. The check reads the App's settings; the installation owner must also accept any permission change.

See the result on the pull request's checks section, or with:

```bash
gh api repos/<owner>/<repo>/commits/<branch>/check-runs --jq '.check_runs[] | {name, conclusion}'
```

Status: automated tests with fake GitHub clients pass, and a Check Run was published successfully on one private test repository. It has not been tried on other repositories.

## Plan provenance (optional, GitHub mode)

By default DeployGuard cannot tell whether `tfplan.json` really came from your CI workflow, so it says the plan is unattested. With provenance checking on, it asks GitHub for the **artifact attestation** of the exact plan file (matched by SHA-256) and verifies the Sigstore signature itself. A plan counts as **verified** only if the attestation was signed by your plan workflow file, in the same repository, for the same pull request (`@refs/pull/<number>/merge`). The result shows as "Plan provenance verified" or "not verified" with a fixed reason, in the web page and the Check Run. It **never changes** the score, level or recommendation.

What you need:

1. **A repository where GitHub artifact attestations are available.** GitHub's documentation limits private-repository attestations to some plans; check yours. Elsewhere the attest step fails.
2. **The attest step in your plan workflow.** The sample workflow has it commented out, with the two job permissions it needs (`id-token: write`, `attestations: write`). Uncomment all three together.
3. **The GitHub App permission Attestations: read.** `go run ./cmd/github-app-setup -provenance ...` requests it (if GitHub rejects the permission name, add it by hand in the App's settings).
4. **A Sigstore trust file**, so no network lookup is needed at startup:

```bash
gh attestation trusted-root > trusted_root.jsonl
export DEPLOYGUARD_PROVENANCE_TRUSTED_ROOT=$PWD/trusted_root.jsonl
```

It covers public-good Sigstore and GitHub's own instance. Refresh the file now and then, because Sigstore rotates keys. Provenance also needs the plan workflow settings (`DEPLOYGUARD_PLAN_WORKFLOW_FILENAME`); with the file missing or invalid the server refuses to start.

What it does and does not prove: it shows the file was produced by that workflow file for that pull request. It does not prove the workflow itself is trustworthy; a pull request author can still edit the workflow in the same pull request, so protect `.github/workflows/` with required reviews. The verification logic is tested offline against a test Sigstore CA; it has **not** been run against a real GitHub attestation.

## Run with Docker (DeployGuard + PostgreSQL)

`docker-compose.yml` starts the whole stack: **DeployGuard** in GitHub mode and **PostgreSQL 17** for verdict history. The image is a static, non-root binary and runs with a read-only filesystem and no extra capabilities. Compose runs GitHub mode only (local mode listens on loopback, which a container cannot expose); use `go run` for local mode.

```bash
cp .env.example .env     # then set the two database passwords and the GitHub settings (below)
docker compose up --build
```

In `.env`, set `POSTGRES_PASSWORD` (admin account, used only to set up and for tests) and `DEPLOYGUARD_DB_PASSWORD` (the account DeployGuard uses). Use URL-safe characters, for example `openssl rand -hex 16`. GitHub settings go in `.env` or in `.env.github` (the file `github-app-setup` creates; it is picked up automatically if present).

How the services are wired:

- **Database account.** On first start, `docker/postgres/init-app.sh` creates a restricted role `deployguard` (no superuser, no `BYPASSRLS`) that owns only the `deployguard` database. DeployGuard refuses to run as a superuser, so it never uses the admin account.
- **Network and TLS.** PostgreSQL publishes no ports; only services on the compose network reach it. DeployGuard requires TLS for any non-loopback database, so the container serves TLS with a self-signed certificate and accepts only TLS connections (`hostssl`). The app connects with `sslmode=require`, which encrypts but does not verify the certificate; use a real certificate and `verify-full` if the database ever leaves this network.
- **Start order and health.** DeployGuard waits until PostgreSQL reports healthy. Data lives in the `pgdata` volume, so verdicts survive restarts (`docker compose down -v` deletes them). The role and TLS setup only run when the volume is first created: after changing `init-app.sh` or the passwords, remove the volume.
- **Port.** DeployGuard is published on `127.0.0.1:8080` only, for your TLS-terminating reverse proxy. Set `DEPLOYGUARD_HOST_PORT` to use another port.
- **AI summary.** The container cannot reach an AI gateway on your host's `127.0.0.1`, and plain HTTP to a non-loopback host is refused. Use an HTTPS provider address, or the summary is silently skipped.

Run the Go tests against this stack's PostgreSQL, inside the same network (the first run downloads Go modules into a volume):

```bash
docker compose --profile test run --rm tests
```

Each integration test creates and drops its own database and role on that server. The browser-script tests run on the host (`node --test ...`).

Stop everything with `docker compose down`.

## Environment variables

Local mode needs none. Provide secrets through the environment or a secret manager and never commit them.

| Variable | Required | Default | Valid value |
| --- | --- | --- | --- |
| `DEPLOYGUARD_LISTEN_ADDRESS` | no | `127.0.0.1:8080` (local), `:8080` (GitHub) | `IP:port`. Local mode needs a loopback IP, e.g. `127.0.0.1:8090` |
| `DEPLOYGUARD_LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, `error`. Logs are JSON on stderr; secrets are redacted |
| `DEPLOYGUARD_AI_PROVIDER` | no (enables AI) | `anthropic` once AI is on | `anthropic`, `openai`, `gemini` or `mistral` |
| `DEPLOYGUARD_AI_BASE_URL` | no (enables AI) | the provider's public API | API address without `/v1`. HTTPS, or HTTP for loopback only. Set it to use a gateway or compatible server |
| `DEPLOYGUARD_AI_API_KEY` | with AI | — | the provider's API key |
| `DEPLOYGUARD_AI_MODEL` | with AI | — | model name |
| `DEPLOYGUARD_GITHUB_APP_ID` | GitHub mode | — | positive integer |
| `DEPLOYGUARD_GITHUB_PRIVATE_KEY_PEM` | GitHub mode | — | the App's RSA private key in PEM format (multi-line, quoted) |
| `DEPLOYGUARD_GITHUB_OAUTH_CLIENT_ID` | GitHub mode | — | Client ID from the App settings |
| `DEPLOYGUARD_GITHUB_OAUTH_CLIENT_SECRET` | GitHub mode | — | Client secret |
| `DEPLOYGUARD_GITHUB_OAUTH_REDIRECT_URL` | GitHub mode | — | exactly the App's callback, e.g. `https://<your-host>/auth/github/callback` |
| `DEPLOYGUARD_PUBLIC_ORIGIN` | GitHub mode | — | HTTPS origin without a path, e.g. `https://<your-host>` |
| `DEPLOYGUARD_GITHUB_WEBHOOK_SECRET` | no (enables webhook and Check Runs) | off | at least 20 characters, e.g. the output of `openssl rand -hex 32`; the same value as in the App's webhook settings. Needs the two plan variables below |
| `DEPLOYGUARD_PLAN_WORKFLOW_FILENAME` | no | — | workflow file name, e.g. `deployguard-plan.yml`. Set together with the next one |
| `DEPLOYGUARD_PLAN_ARTIFACT_NAME` | no | — | artifact name, e.g. `deployguard-plan` |
| `DEPLOYGUARD_PLAN_JSON_FILENAME` | no | `tfplan.json` | file name inside the artifact, no path |
| `DEPLOYGUARD_DATABASE_URL` | no (GitHub mode) | off | `postgres://user:password@host:5432/db`. A remote host needs `sslmode=require`, `verify-ca` or `verify-full`. Needs a role without superuser or `BYPASSRLS` |
| `DEPLOYGUARD_HISTORY_FILE` | no | `history.jsonl` in the user config folder | local mode only: an absolute file path, or `off`. Relative paths are ignored (history stays off) |
| `DEPLOYGUARD_RETENTION_DAYS` | no | `90` | whole days, 1 to 3650, to keep stored verdicts |
| `DEPLOYGUARD_PR_COMMENTS` | no | `false` | `true` also keeps one comment per pull request (needs the webhook and the App permission Pull requests: write; see below) |
| `DEPLOYGUARD_PROVENANCE_TRUSTED_ROOT` | no | off | path to a Sigstore trust file from `gh attestation trusted-root`. Turns on plan provenance checks; needs the plan workflow settings |
| `DEPLOYGUARD_SESSION_TTL` | no | `30m` | duration from `5m` to `24h` |
| `DEPLOYGUARD_GITHUB_API_BASE_URL`, `DEPLOYGUARD_GITHUB_WEB_BASE_URL` | no | `https://api.github.com`, `https://github.com` | HTTPS URLs (for GitHub Enterprise) |
| `DEPLOYGUARD_TRUSTED_PROXY_HEADER` | no | — | header that **your** proxy sets with the client IP, e.g. `X-Forwarded-For` |

## Troubleshooting

**`... is already in use by another program`, or the server will not start on port 8080.**
Another program uses the port. Pick another:

```bash
DEPLOYGUARD_LISTEN_ADDRESS=127.0.0.1:8090 go run ./cmd/deployguard
```

See who uses it: `lsof -nP -iTCP:8080 -sTCP:LISTEN`.

**"invalid host" (403) in the browser.**
Open exactly the address in the log, `http://127.0.0.1:8080`. `localhost` does not match the configured address, so it is rejected on purpose.

**403 "Invalid request origin" after clicking Analyze.**
This was a bug in older builds. Update the code, restart the server and hard-refresh the page.

**"We couldn't read that plan" (422) or "Invalid Terraform plan JSON".**
Wrong file. You need the JSON from `terraform show -json tfplan`, not the binary `tfplan`, and at most 10 MiB.

**"GitHub mode is on because these variables are set: …".**
If any GitHub-related variable is set (even the webhook secret or `DEPLOYGUARD_PUBLIC_ORIGIN`), DeployGuard assumes GitHub mode and requires the full set. The message lists the variables that triggered it and the ones still missing (names only, never values). For local mode, remove all `DEPLOYGUARD_*` variables from the current shell and comment out the GitHub lines in `.env`:

```bash
unset $(env | grep -o '^DEPLOYGUARD_[A-Z_]*')
```

**`local mode requires a loopback IP listen address`.**
In local mode the address must be a loopback IP such as `127.0.0.1:8080`. `0.0.0.0` and `localhost` do not work.

**No AI summary.**
Check that `DEPLOYGUARD_AI_PROVIDER` or `DEPLOYGUARD_AI_BASE_URL` is set, together with `DEPLOYGUARD_AI_API_KEY` and `DEPLOYGUARD_AI_MODEL`, and that the log shows `"ai_enabled":true`. A key without a provider or address does not enable AI. An unknown provider name stops the server at startup and lists the valid names. A slow or unreachable service is skipped silently. An `http://` address with a non-loopback host (for example `http://host.docker.internal`) is rejected; use HTTPS.

**GitHub sign-in does not work.**
It needs an HTTPS address, because session cookies are `Secure`. `DEPLOYGUARD_GITHUB_OAUTH_REDIRECT_URL` must also match the GitHub App's Callback URL exactly. With a temporary tunnel, update both whenever its address changes.

**No Check Run appears on the pull request.**
Check in order: the startup log for `missing a permission` warnings; the App has the Pull request and Workflow run events; `DEPLOYGUARD_GITHUB_WEBHOOK_SECRET` and the plan variables are set; the plan workflow finished successfully; the App is installed on that repository; the `webhook audit` lines in the server log. If the log shows `workflow mismatch`, update the code: that bug is fixed.

**Tests cannot run because Node.js is missing.**
`go test ./...` does not need Node. Only `node --test …` does.

## Security boundaries

- Plans can contain secrets. Uploads are processed in memory and not kept longer than needed. Do not log plans.
- An uploaded plan is tied to the selected PR but is **not** cryptographically attested. Verify its source yourself.
- Actions artifacts keep plan data for their whole retention period. Keep it short and restrict access.
- The AI summary sends finding text and resource addresses to the service you configure. Resource names come from the repository, so a model could in theory be misled; the verdict never depends on it.
- DeployGuard needs no AWS credentials and no write access to your code.

## Not done yet

PR comments, cryptographic plan provenance, PostgreSQL persistence and billing.

## Documentation

- [docs/architecture.md](docs/architecture.md): architecture and MVP boundaries
- [docs/github-app.md](docs/github-app.md): GitHub App setup
- [docs/api/openapi.yaml](docs/api/openapi.yaml): HTTP interface

## License

[MIT](LICENSE).
