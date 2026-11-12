# DeployGuard MVP architecture

## Scope

DeployGuard receives Terraform plan JSON associated with a GitHub pull request,
evaluates it with deterministic AWS-focused rules, and publishes a review using
GitHub Checks (with a concise PR comment where useful). The result includes an
overall score and level, cost/reliability/security dimensions, blast radius,
findings, a plain-language explanation, and a SAFE / REVIEW / BLOCK
recommendation.

The MVP is a single Go service (a modular monolith) plus PostgreSQL only when
durable state is needed. Local development uses Docker. It is not a Terraform
runner, deployment platform, general cloud scanner, or general-purpose AI
assistant. It has no AWS write permissions and needs no AWS credentials.

## Component boundaries

```text
GitHub OAuth / user session
          |
          v
Authenticated web edge -- CSRF, size limits, validate user and PR access
          |
          v
GitHub adapter -- verify App installation and current PR head;
                  accept JSON upload or optional scoped Actions artifact
          |
          v
Plan parser -- validate and normalize Terraform plan JSON
          |
          v
Risk engine -- deterministic checks produce typed facts and findings
          |
          +--> Scoring and recommendation -- derive from rule output
          |
          +--> Optional explanation adapter -- verbalize supplied facts only
          |
          v
Authenticated review page -- show deterministic analysis for the selected PR
```

Keep the core domain independent of HTTP, GitHub SDKs, PostgreSQL, and any AI
provider. Adapters translate external data to and from domain types. The parser
and rules engine must be usable and testable without network access.

### Trust boundaries and plan input

Treat the webhook, browser selectors, repository metadata, plan artifact, and
all plan values as untrusted. Verify webhook signatures and user authorization,
installation, repository identity, pull-request identity, and current head
through GitHub before analysis. Never accept a repository identity from the
plan itself. A direct upload is associated with the selected current PR head,
but its source commit is not cryptographically attested.

The canonical input is Terraform plan JSON uploaded directly or optionally
retrieved from an explicitly configured Actions artifact. The SaaS backend must
never run `terraform`, provider plugins, scripts, or other repository code.
Keep plan bytes in memory or short-lived
temporary storage only for the analysis request, and remove temporary data after
processing. Do not log plan contents.

## Analysis contract

The parser normalizes resource addresses, types, actions, before/after values,
and relevant plan metadata while preserving unknown or sensitive values as
unknown/redacted. It must not interpret missing or unknown data as a safe value.

The initial deterministic checks cover:

1. Resource replacement
2. Production resource deletion
3. CloudWatch alarm deletion
4. Security group becoming more permissive
5. Encryption being disabled
6. RDS becoming publicly accessible
7. Large resource-count changes
8. Critical-resource changes
9. Resource size/capacity increase
10. Monitoring coverage regression

Rules emit typed findings with evidence references, severity, and affected
resources. Scoring, dimension summaries, blast radius, and recommendation are
derived from those findings and normalized changes. Explanations can only
rephrase this structured result. If explanation generation is unavailable,
publish a deterministic explanation from the same facts.

## GitHub interaction

Use a GitHub App for installation-scoped authorization and GitHub user OAuth
for browser sessions. Keep permissions limited to repository, pull-request,
and optional Actions read access. Do not request write access to AWS. Check Run
publishing remains a later increment; the current web flow renders the
deterministic analysis without writing back to the PR.

Prefer a Check Run as the authoritative structured result. The optional PR
comment renders the same result (it is not a second analysis path): it names
the commit, is edited in place, is replaced by a new comment when the verdict
worsens so people are notified, and is skipped when the PR head has moved on.

Duplicate webhook deliveries are handled in two layers. A redelivered
`X-GitHub-Delivery` ID is acknowledged and not processed again (bounded
in-memory memory per instance, forgotten on restart); and the stored verdict is
idempotent per commit (one row per installation, repository, pull request and
head SHA, replaced when the commit is analyzed again), so a repeat that slips
through, across restarts or instances, cannot add a duplicate history row.

## Security and operations

- Enforce webhook signature verification, payload size limits, request timeouts,
  and rate limits at the HTTP edge.
- Bind every request and stored record to the verified GitHub installation and
  repository. Derive tenant identity from the validated installation, never
  from user-supplied plan fields.
- Redact credentials and sensitive plan values from logs; log identifiers,
  outcome, duration, and audit events instead.
- Use least-privilege GitHub permissions and short-lived installation tokens.
- Keep plans ephemeral. Any later persistence must have an explicit retention
  policy and tenant-scoped access checks.
- Audit security-relevant actions such as webhook acceptance/rejection,
  analysis completion, and check publication without recording plan contents.
- No AWS credentials, AWS API calls, Terraform execution, or automatic
  infrastructure changes in the MVP.

## Planned repository structure

```text
.
├── cmd/
│   └── deployguard/       # service entry point (added with service bootstrap)
├── internal/
│   ├── domain/            # normalized plan, findings, score, recommendation
│   ├── plan/              # Terraform plan JSON parsing and validation
│   ├── risk/              # deterministic rules and aggregation
│   ├── github/            # webhook, App auth, Checks API adapters
│   ├── httpapi/           # HTTP handlers, middleware, limits
│   ├── explain/           # optional fact-constrained explanation adapter
│   └── audit/             # security audit event interface/implementation
├── migrations/            # introduced only if durable state is required
├── testdata/              # minimized, sanitized plan JSON fixtures
├── docs/                  # architecture and product/operations decisions
├── Dockerfile             # service image, added with service bootstrap
├── compose.yaml           # local development services, added when needed
├── go.mod                 # added with the first Go implementation increment
└── README.md
```

These are boundaries, not a requirement to create empty packages up front.
Create each package when its first concrete component is implemented; avoid
framework layers and interfaces that do not yet serve a real boundary.

## Development sequence

1. Architecture and repository structure (this increment).
2. Domain model and analysis output contract.
3. Terraform plan JSON parser and validation.
4. Deterministic risk rules and aggregation.
5. Unit tests for parsing, rules, scoring, and recommendations.
6. GitHub App and webhook integration.
7. Authenticated GitHub web review via direct Terraform JSON upload and
   optional scoped Actions artifacts.
8. Check Runs and PR feedback.
9. Persistence only for demonstrated needs, followed by SaaS billing.

Persistence is deliberately deferred: the first analysis path can be stateless,
with bounded idempotency/retention decisions made alongside GitHub integration.
