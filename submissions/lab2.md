# Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile

Tool: `threagile/threagile:0.9.1` (the binary inside reports version `1.0.0`, which is expected).
Host: macOS 15.3.1, arm64 — the image is `linux/amd64`, so every run prints a platform warning and
`Fontconfig error: No writable cache directories`. Both are noise; all eight output files are produced.

## Task 1

### Severity table (baseline)

```console
$ jq 'length' labs/lab2/output/risks.json
23

$ jq '[.[].severity] | group_by(.) | map({severity: .[0], count: length})' labs/lab2/output/risks.json
[
  { "severity": "elevated", "count": 4 },
  { "severity": "low",      "count": 5 },
  { "severity": "medium",   "count": 14 }
]
```

| Severity | Count |
|---|---:|
| critical | 0 |
| high | 0 |
| elevated | 4 |
| medium | 14 |
| low | 5 |
| **Total** | **23** |

`stats.json` agrees and adds the status split: all 23 are `unchecked`, none accepted or mitigated.

### Top five, ranked properly

Sorting on the severity string alphabetically would put `elevated` above `high`, so the rank comes from
an explicit order array:

```console
$ jq -r '["critical","high","elevated","medium","low"] as $order
    | [.[] | {sev: .severity, rule: .category, asset: .most_relevant_technical_asset}]
    | sort_by(.sev as $s | $order | index($s))
    | .[:5][] | "\(.sev)\t\(.rule)\t\(.asset)"' labs/lab2/output/risks.json
elevated	unencrypted-communication	user-browser
elevated	unencrypted-communication	reverse-proxy
elevated	missing-authentication	juice-shop
elevated	cross-site-scripting	juice-shop
medium	missing-vault	juice-shop
```

| # | Severity | Rule ID | Asset | STRIDE | Why that letter |
|---|---|---|---|---|---|
| 1 | elevated | `unencrypted-communication` | `user-browser` | **I** — Information Disclosure | The `Direct to App (no proxy)` link carries `tokens-sessions` over `http`, so anyone on the path reads the session token off the wire and never has to break authentication at all. |
| 2 | elevated | `unencrypted-communication` | `reverse-proxy` | **I** — Information Disclosure | The proxy terminates TLS and then forwards to the app over plain `http`, so the traffic is in clear text again for the second hop — the confidentiality the user thinks HTTPS bought them ends at the proxy. |
| 3 | elevated | `missing-authentication` | `juice-shop` | **E** — Elevation of Privilege | The `To App` link declares `authentication: none`, so the app cannot distinguish the proxy from anything else that can reach port 3000 and will serve a forged request with the same trust. |
| 4 | elevated | `cross-site-scripting` | `juice-shop` | **T** — Tampering | Injected script rewrites what the page does inside the victim's session, so the attacker is tampering with the data and the behaviour the user sees rather than reading it from outside. |
| 5 | medium | `missing-vault` | `juice-shop` | **I** — Information Disclosure | With no vault asset in the model the JWT signing key and other secrets live in config or the image, so one read of the filesystem discloses the secrets that protect everything else. |

The letters match Threagile's own classification in `report.pdf` (chapter "STRIDE Classification of
Identified Risks"), which files these under Information Disclosure, Elevation of Privilege and Tampering
respectively.

### The trust-boundary crossing

The arrow labelled **`http`** running from **User Browser** straight down to **Juice Shop Application** —
the `Direct to App (no proxy)` link, which is risk #1 above.

It crosses **two** boundaries in one hop: it starts in **Internet** (where `user-browser` lives), passes
through **Host**, and terminates inside **Container Network** (where `juice-shop` lives). The nesting is
visible in the DFD as three dotted blue rectangles, and this arrow goes from the outermost to the innermost
without stopping.

Why an attacker spends time on it: it is the *only* inbound path that skips the reverse proxy entirely.
Everything the proxy exists to provide — TLS termination, HSTS, CSP, any header hardening or request
filtering — is simply not on this route, and the link still carries `tokens-sessions` as `data_assets_sent`.
So it is both the weakest inbound path and the one that reaches deepest into the architecture; the sibling
`https` arrow into Reverse Proxy is strictly harder to attack for exactly the same prize. An attacker on the
same network segment gets session tokens by listening, with no exploit and nothing to trigger server-side.

## Task 2

### Hardening applied

`labs/lab2/threagile-model-secure.yaml`, five edits (`title` kept at 25 characters so the Excel and PDF
steps still run):

| # | Where | Field | Baseline | Secure |
|---|---|---|---|---|
| 1 | `user-browser` → `Direct to App (no proxy)` | `protocol` | `http` | `https` |
| 2 | `reverse-proxy` → `To App` | `protocol` | `http` | `https` |
| 3 | `reverse-proxy` → `To App` | `authentication` | `none` | `client-certificate` |
| 4 | `reverse-proxy` → `To App` | `authorization` | `none` | `technical-user` |
| 5 | `juice-shop` and `persistent-storage` | `encryption` | `none` | `data-with-symmetric-shared-key` |

`client-certificate` is a deliberate choice over `credentials` or `token`: mutual TLS satisfies "declares
how it authenticates" without handing the model a shared secret it would then have to store, and it does
not add a `missing-authentication-second-factor` finding the way `session-id` or `token` would.

### Baseline vs secure

```console
$ jq 'length' labs/lab2/output-secure/risks.json
18
```

| Severity | Baseline | Secure | Δ |
|---|---:|---:|---:|
| critical | 0 | 0 | 0 |
| high | 0 | 0 | 0 |
| elevated | 4 | 1 | **−3** |
| medium | 14 | 12 | **−2** |
| low | 5 | 5 | 0 |
| **Total** | **23** | **18** | **−5 (−21.7 %)** |

Every elevated finding except one is gone. The one that survives is the XSS risk.

### Rules in `gone:`, and the field that removed each

```console
$ echo "gone:";  comm -23 /tmp/base-rules.txt /tmp/secure-rules.txt
gone:
missing-authentication
unencrypted-asset
unencrypted-communication
$ echo "new:";   comm -13 /tmp/base-rules.txt /tmp/secure-rules.txt
new:
```

| Rule ID | Instances removed | Field change that removed it |
|---|---:|---|
| `unencrypted-communication` | 2 | `protocol: http` → `https` on both links into the application (edits 1 and 2). The rule tests whether the link's protocol is an encrypted one; `https` is, `http` is not. |
| `missing-authentication` | 1 | `authentication: none` → `client-certificate` on `reverse-proxy → To App` (edit 3). The rule fires only on links whose authentication is `none` into an asset above a confidentiality/integrity threshold. |
| `unencrypted-asset` | 2 | `encryption: none` → `data-with-symmetric-shared-key` on `juice-shop` and `persistent-storage` (edit 5). One instance per asset. |

Nothing appeared in `new:` — 5 findings removed, 0 introduced, which is the check that the edits changed
existing assets rather than adding new ones.

### Two rules that still fire, and why no edit of mine could remove them

**`cross-site-scripting` (elevated, `juice-shop`).** There is no field in the Threagile schema that says
"this application escapes its output". The rule fires on the combination of `technology: web-server`,
`custom_developed_parts: true` and an inbound web-protocol link, and all three of those are true statements
about Juice Shop that I have no business editing. Whether the risk is real depends on the template code, which
the model cannot see.

**`container-baseimage-backdooring` (medium, `juice-shop`).** This fires from `machine: container` — the app
genuinely runs in a container pulled from Docker Hub. The mitigation is provenance work outside the model:
a signed base image, a pinned digest, and a scan of what is in it. Editing `machine:` to something else would
not mitigate anything, it would just describe a system that does not exist.

### What is left, and what it would take

The five findings that dropped were all *declarative* ones — properties the YAML can state outright: whether
a channel is encrypted, whether a link authenticates, whether an asset is encrypted at rest. What remains is
three other kinds. Code-level flaws (`cross-site-scripting`, `cross-site-request-forgery`,
`server-side-request-forgery`) need output encoding, anti-CSRF tokens and egress allow-listing in the source,
and are closed by Labs 5 and 6, not by a field. Missing-component findings (`missing-vault`, `missing-waf`,
`missing-identity-store`, `missing-build-infrastructure`) need something built and then modelled — adding the
asset to the YAML alone would be modelling a control nobody deployed. Supply-chain and operational findings
(`container-baseimage-backdooring`, `missing-hardening`) are closed by signing and scanning the image, which
is Labs 4, 7 and 8.

The one that **no YAML edit can close** is `cross-site-scripting`. Threagile reasons about architecture: assets,
links, protocols and boundaries. Output encoding is a property of a line of source code inside the asset, invisible
at that altitude — the only way to make the finding disappear from `risks.json` without lying about the
architecture is `risk_tracking`, and marking a risk `mitigated` is a statement about work done elsewhere, not a
change to the model. That is the honest limit of architecture-level threat modelling, and it is exactly why this
lab feeds Lab 5.

## Bonus

`labs/lab2/threagile-model-auth.yaml`, written over the `-create-stub-model` skeleton. It models one feature —
the login path — at endpoint granularity: **6 technical assets** (`login-client`, `login-endpoint`,
`token-service`, `admin-endpoint`, `credential-store`, `key-vault`), **7 communication links**, **5 data assets**
(`login-credentials`, `jwt-signing-key`, `access-token`, `user-directory`, `admin-action-log`), and three nested
boundaries (Public Internet → Auth Tier → Secret Tier). The JWT signing key is its own data asset, stored only in
`key-vault` and read only by `token-service`. Every link declares both `authentication` and `authorization`; the
single `authorization: none` is on `Submit Credentials`, which is pre-authentication by definition — there is no
established principal to authorize while one is still being proven, and the field is declared explicitly rather
than omitted.

The authorisation check on the admin endpoint is the `Verify Token And Role` link
(`admin-endpoint` → `token-service`, `authentication: token`, `authorization: enduser-identity-propagation`):
the role is re-derived from the verified token on every call, before `Read Write User Records` touches a row.

### Severity table

```console
$ jq 'length' labs/lab2/output-auth/risks.json
42

$ jq '[.[].severity] | group_by(.) | map({severity: .[0], count: length})' labs/lab2/output-auth/risks.json
[
  { "severity": "elevated", "count": 17 },
  { "severity": "high",     "count": 2 },
  { "severity": "low",      "count": 4 },
  { "severity": "medium",   "count": 19 }
]
```

| Severity | Count |
|---|---:|
| critical | 0 |
| high | 2 |
| elevated | 17 |
| medium | 19 |
| low | 4 |
| **Total** | **42** |

Seven rule IDs fire here that never fired on the architecture model: `sql-nosql-injection`,
`unguarded-access-from-internet`, `missing-identity-provider-isolation`, `missing-vault-isolation`,
`missing-identity-propagation`, `missing-network-segmentation`, `dos-risky-access-across-trust-boundary`.
Note also the two highest severities in the whole lab — the only `high` findings anywhere — are in this model.

### Three risks the architecture model did not surface

| Rule ID | Severity | STRIDE | Instance | Mitigation |
|---|---|---|---|---|
| `sql-nosql-injection` | **high** | **T** — Tampering | `Login Endpoint` against `Credential Store` via `Verify Password Hash` (and the same at `Admin Endpoint`) | Bind the email and password as query parameters instead of concatenating them into the lookup, so a crafted email cannot change the shape of the authentication query. |
| `unguarded-access-from-internet` | elevated | **E** — Elevation of Privilege | `Admin Endpoint` by `Login Client` via `Call Admin API` | Put the privileged route behind the reverse proxy or a gateway rather than letting an internet-facing client reach it directly, so the role check is not the only thing between the internet and every user record. |
| `missing-vault-isolation` | medium | **E** — Elevation of Privilege | `Signing Key Vault` sharing a segment with lower-protected assets | Move the vault into its own network segment with its own policy, so compromising the login endpoint does not put an attacker one hop from the key that mints every token. |

The letters are Threagile's own, from the STRIDE chapter of `labs/lab2/output-auth/report.pdf`.

### What the feature-level model showed that the architecture-level one could not

The architecture model has one box called "Juice Shop Application" with a 70 % RAA, and every authentication
concern collapses into it — `missing-authentication` on one link and `missing-vault` as a generic "no secret
storage in this model" note. Splitting that box into a login endpoint, a token service, a credential store and
an admin endpoint made the *path* visible, and with it two `high` SQL-injection findings on the credential
lookup and a key-custody finding on the vault, neither of which has anywhere to attach when the login logic,
the token logic and the data store are the same node. The inverse is also true and worth saying: `missing-vault`
and `missing-identity-store` disappear here precisely because this model *does* declare a vault and an identity
store — so the two models disagree, and the disagreement is the point rather than a mistake. Granularity is a
modelling decision that changes which risks are expressible at all, not just how many are counted.
