# Lab 1 — Deploy OWASP Juice Shop & Set Up the Course Workflow

## Triage report

### Asset

| Field | Value |
|---|---|
| Image tag | `bkimminich/juice-shop:v20.0.0` |
| Image digest | `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0` |
| Image platform / size | `linux/arm64`, 132 574 416 bytes (~133 MB), built 2026-05-12 |
| Image runs as | UID `65532` (non-root), exposes `3000/tcp` |
| Host OS | macOS 15.3.1 (build 24D70), arm64 (Apple Silicon) |
| Docker version | Client and server 29.2.1 (build a5c7197), Docker Desktop |

The digest came from `RepoDigests` on the image, not from `{{.Image}}` on the container:

```console
$ docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Deployment

```bash
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
```

- **Access URL:** <http://127.0.0.1:3000>
- **Bound to localhost only:** yes. `docker ps` reports `127.0.0.1:3000->3000/tcp`, not `0.0.0.0:3000->3000/tcp`. The publish spec `127.0.0.1:3000:3000` pins the host side of the port mapping to the loopback interface, so the listener is reachable only from this machine. A bare `-p 3000:3000` binds `0.0.0.0` and publishes an application that is *intentionally* full of exploitable flaws to every interface the host has — the university Wi-Fi, any VPN, any hotspot. Docker also writes its own rules into the host packet filter, so a local firewall that looks closed can still let the published port through. Deliberately vulnerable targets stay on loopback.
- **Restart policy:** `no` (`MaximumRetryCount` 0) — the container does not come back after a daemon restart or a crash. That is the right choice for a throwaway lab target: it should not silently reappear on the next reboot. A long-lived service would use `unless-stopped`.

```console
$ docker inspect juice-shop --format 'RestartPolicy={{.HostConfig.RestartPolicy.Name}} MaxRetry={{.HostConfig.RestartPolicy.MaximumRetryCount}}'
RestartPolicy=no MaxRetry=0
```

### Health

```console
$ docker ps --filter name=juice-shop --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
NAMES        STATUS         PORTS
juice-shop   Up 2 minutes   127.0.0.1:3000->3000/tcp

$ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3000
HTTP 200

$ curl -s http://127.0.0.1:3000/rest/admin/application-version
{"version":"20.0.0"}

$ curl -s http://127.0.0.1:3000/api/Products | jq '.data | length'
46
```

All four match what the lab expects: `HTTP 200`, version `20.0.0`, 46 products, and a container bound to `127.0.0.1:3000`. The app needed roughly 20 seconds after `docker run` before the first request returned 200.

### Surface

What I found browsing <http://127.0.0.1:3000> and watching the Network tab:

- **Login and registration.** `Account → Login` (`/#/login`) is a plain email/password form with "Remember me", a "Forgot your password?" link, and a "Log in with Google" button — so there is a third-party OAuth path in addition to local credentials. Registration (`/#/register`) asks for email, a password of only **5–40 characters** with no complexity or breach check, and a mandatory security question the form itself labels *"This cannot be changed later!"*. That security answer is the recovery factor for the whole account, and it is the sort of thing (favourite pet, company you first worked for) that is usually guessable or public.
- **Products.** One flat grid, 46 items, prices and descriptions rendered client-side. The catalogue comes from `GET /api/Products`, which returns the full `{"data": [...]}` envelope with **no session and no Authorization header** — `curl` from a cold shell gets the same 46 records the browser does. Clicking a product opens a dialog whose reviews are fetched from `GET /rest/products/1/reviews`, also unauthenticated, and the response contains reviewer **email addresses** (`admin@juice-sh.op`, `basil@juice-sh.op`) alongside the review text. So customer-identifying data is readable by anyone who can reach port 3000.
- **Admin / account area.** The account menu shows only "Login" while signed out. But the admin route ships in the client bundle and is routable: navigating to `/#/administration` renders the app shell and then a red in-page banner, **"403 — You are not allowed to access this page!"**. That is an Angular route guard, i.e. a *client-side* decision — the route, its component and its API calls are all present in JavaScript the browser already downloaded. The server does back it up for the data itself (`GET /api/Users` → `401`), but `GET /rest/admin/application-configuration` returns **200 unauthenticated** and hands out the whole application config (`application`, `challenges`, `ctf`, `hackingInstructor`, `memories`, `products`, `server` keys). Separately, `GET /ftp` returns a **browsable directory listing**: `acquisitions.md`, `announcement_encrypted.md`, `coupons_2013.md.bak`, `eastere.gg`, `encrypt.pyc`, `incident-support.kdbx`, `legal.md`, `package-lock.json.bak`, `package.json.bak`, `suspicious_errors.yml`, and a `quarantine/` folder.
- **Console errors.** The DevTools console was **clean on load** — no uncaught exceptions on the product listing, the login page or the registration page. The app does not fail loudly in the console; it fails loudly in the UI instead. After I probed `GET /api/Users` without a token, the app popped its own banner: *"You successfully solved a challenge: Error Handling (Provoke an error that is neither very gracefully nor consistently handled.)"*. So error handling is inconsistent by design, and the app is willing to tell an anonymous visitor that it just mishandled something.
- **Local storage and cookies.** Nothing is pre-populated before login: `localStorage` and `sessionStorage` are both **empty**. `document.cookie` returns only `language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss` — three UI-preference cookies, all readable from JavaScript, none of them `HttpOnly` and none `Secure` (the app is served over plain HTTP, so `Secure` would break them anyway). The cookie banner itself is decorative: dismissing it sets `cookieconsent_status=dismiss` client-side and nothing about tracking actually changes.

### Headers

```console
$ curl -sI http://127.0.0.1:3000 | head -20
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Mon, 21 Sep 2026 08:00:20 GMT
ETag: W/"26af-1a0c2faee5a"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Mon, 21 Sep 2026 08:00:34 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

| Header | Present? | Note |
|---|---|---|
| `Content-Security-Policy` | **Missing** | Nothing constrains script sources, so any injected `<script>` or inline handler executes with full page privilege. |
| `Strict-Transport-Security` | **Missing** | The app is served over plain HTTP, so there is no TLS to pin — but that is the finding, not an excuse. |
| `X-Content-Type-Options` | Present | `nosniff` |
| `X-Frame-Options` | Present | `SAMEORIGIN` — framing by third-party origins is refused. |

Two of the four are missing: **CSP** and **HSTS**. Both fall under **A02:2025 — Security Misconfiguration**. Two more things in that output are worth flagging even though the lab did not ask: `Access-Control-Allow-Origin: *` lets any origin read responses cross-site, and `X-Recruiting: /#/jobs` is a custom header advertising an internal route to every client.

### Top 3 risks

**1. Unauthenticated file store at `/ftp` — A01:2025, Broken Access Control.**
`GET /ftp` returns a directory index that anyone who can reach the app can browse, and the contents are not marketing copy: `package.json.bak` and `package-lock.json.bak` disclose the exact dependency tree an attacker would use to pick a known CVE, `coupons_2013.md.bak` is a leaked business artifact, and `incident-support.kdbx` is a **KeePass credential database** sitting in the open. This is the highest-value finding on the box because it needs no account, no payload and no skill — one `curl` gets it, and an offline crack of the `.kdbx` turns a read-only anonymous fetch into real credentials.

**2. No Content-Security-Policy and no HSTS, with wildcard CORS — A02:2025, Security Misconfiguration.**
The response carries `nosniff` and `SAMEORIGIN` but no `Content-Security-Policy` at all, so there is no second line of defence once anything reaches the DOM: a single stored-XSS payload in a product review executes with the page's full privilege and can read the session. `Access-Control-Allow-Origin: *` compounds it by letting any origin read API responses cross-site. `Strict-Transport-Security` is absent and the app runs on plain HTTP, so every request and every credential crosses the wire in cleartext and is trivially downgradable the moment this is reachable off-loopback.

**3. Weak account-recovery and password policy — A07:2025, Authentication Failures.**
Registration accepts a password of **five characters** with no complexity rule, no breach-corpus check and no lockout visible on the login form, which puts online guessing well within reach. Worse, the account's recovery factor is a security question the UI explicitly says *cannot be changed later* — so a guessable answer is a permanent, unrotatable bypass of the password entirely. A weak secret you can rotate is a bad day; a weak secret you can never rotate is a standing back door into the account.

### Keeping the container

```console
$ docker stop juice-shop
juice-shop
```

Stopped, **not** removed — Labs 4, 5, 7, 8 and 10 generate the SBOM of, scan, sign and triage this same image.

---

## PR template

- **File path:** [`.github/PULL_REQUEST_TEMPLATE.md`](../.github/PULL_REQUEST_TEMPLATE.md)
- **Sections:** `## Goal` (one sentence), `## Changes` (bullet list), `## Testing` (commands and observed output), `## Artifacts & Screenshots`
- **Checklist items:**
  - `Title follows feat(labN): <topic>`
  - `No secrets or large temp files committed`
  - `submissions/labN.md exists`
- **Draft PR showing the auto-filled description:** <https://github.com/jakefish18/DevSecOps-Intro/pull/1>

The draft PR's description is that template, filled in: the four headings and the three checklist items in the PR body come straight from the file. GitHub reads the pull-request template from the repository a PR is opened *against*, so the description box auto-fills for any PR whose base branch already carries `.github/PULL_REQUEST_TEMPLATE.md` — in this fork that is every PR opened after this branch lands on `main`.

---

## GitHub community

Starred [inno-devops-labs/DevSecOps-Intro](https://github.com/inno-devops-labs/DevSecOps-Intro) and [simple-container-com/api](https://github.com/simple-container-com/api); following the professor [@Cre-eD](https://github.com/Cre-eD), the TAs [@Naghme98](https://github.com/Naghme98) and [@pierrepicaud](https://github.com/pierrepicaud), and classmates from the cohort.

Stars are the only cheap, public signal a maintainer gets that unpaid work is worth continuing — they drive a project up GitHub search and trending, which is how the next contributor and the next downstream user find it at all, and a starred repo is far easier to justify to an employer as time well spent. Following people turns a class into a graph I can actually read: their PRs and pushes show up in my feed, so when I hit a wall on a lab I already know who solved that piece last week and whose branch to look at instead of starting from zero.

---

## Bonus: CI smoke test

- **Workflow path:** [`.github/workflows/lab1-smoke.yml`](../.github/workflows/lab1-smoke.yml)
- **Run URL:** <https://github.com/jakefish18/DevSecOps-Intro/actions/runs/35576399444>
- **Run duration:** 21 seconds (`2026-09-21T08:09:09Z` → `2026-09-21T08:09:30Z`), conclusion `success`

```yaml
on:
  pull_request:
    branches: [main]

permissions:
  contents: read
```

The workflow starts `bkimminich/juice-shop:v20.0.0` as a `services:` container with `3000:3000` published to the runner, then polls `http://localhost:3000/rest/admin/application-version` with `curl --silent --fail` once a second for up to 60 attempts, exiting 0 on the first 200 and exiting 1 if the loop runs out. `--fail` is what makes a 4xx/5xx count as a failure instead of a successful fetch of an error page. The loop succeeded on attempt 3 (`Juice Shop answered after 3s`) because the runner brings `services:` containers up and waits on them *before* the first step runs, so most of Juice Shop's 20–30 second CI boot had already happened by the time the poll started. The 60-second budget still earns its place: with the `docker run -d` variant the step owns the whole boot, and a 10-second loop fails on a perfectly healthy app.

It triggers on `pull_request`, not `pull_request_target` — `pull_request_target` runs the *base* branch's workflow with a writable token and repository secrets in the context of untrusted fork code, which is the classic way a CI pipeline gets turned into a credential-exfiltration primitive. `permissions: { contents: read }` at workflow level means even the built-in `GITHUB_TOKEN` cannot write to the repo. The image is pinned by tag here, which the lab accepts for this first workflow; Lecture 4 covers pinning by digest, and the digest for this exact image is in the triage report above.

**Curl output excerpt from the job log:**

```
2026-09-21T08:09:25.3419231Z ##[group]Run for i in $(seq 1 60); do
2026-09-21T08:09:25.3420494Z   if curl --silent --fail http://localhost:3000/rest/admin/application-version; then
2026-09-21T08:09:25.3459484Z shell: /usr/bin/bash -e {0}
2026-09-21T08:09:25.3460333Z ##[endgroup]
2026-09-21T08:09:27.3911583Z {"version":"20.0.0"}
2026-09-21T08:09:27.3912054Z Juice Shop answered after 3s
```
