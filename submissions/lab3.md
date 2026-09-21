# Lab 3 — Secure Git: Signed Commits, Secret Scanning, and History Hygiene

Environment: macOS 15.3.1 (arm64), Git 2.39.5 (Apple Git-154), gitleaks 8.30.1,
pre-commit 4.6.2, git-filter-repo a40bce548d2c. The Python tools are installed with
Homebrew rather than `pipx` — the `externally-managed-environment` (PEP 668) problem the
lab warns about is Debian/Ubuntu-specific, and `brew install` gives the same isolated
environments on macOS.

## Task 1

### Configuration

| Key | Value |
|---|---|
| `gpg.format` | `ssh` |
| `user.signingkey` | `/Users/insafgarifullin/.ssh/github.pub` |
| `commit.gpgsign` | `true` |
| `tag.gpgsign` | `true` |
| `gpg.ssh.allowedSignersFile` | `/Users/insafgarifullin/.config/git/allowed_signers` |
| `user.email` | `jakefish.work@gmail.com` |

Two deviations from the lab's literal commands, both deliberate:

1. **The key is `~/.ssh/github.pub` (RSA 3072), not a fresh `~/.ssh/id_ed25519`.** This machine had
   no `id_*` key at all. Rather than generate a second passphrase-less private key, I reused the key
   already registered with GitHub, which then gets added a second time under the Signing Key role —
   exactly the "same key bytes go in twice, once per role" case in the lab's pitfalls.
2. **`user.email` had to be set first.** It was unset globally, so Git was deriving an author address
   from the hostname: my Lab 1 and Lab 2 commits went up as
   `insafgarifullin@Insafs-MacBook-Pro.local`, and the GitHub API reports `author: null` for them —
   not linked to my account, and permanently unverifiable. That is the repudiation problem in its
   most boring form, and I had caused it myself without noticing.

The `allowed_signers` file is what lets Git check its own signatures offline. Its format is
`<email> namespaces="git" <the whole public key line>`; without it Git signs happily and then cannot
verify what it just wrote.

### Proof: `git log --show-signature -1`

```console
$ git log --show-signature -1
commit cda2b888a925226d7829d8dde29ec3db4005705b
Good "git" signature for jakefish.work@gmail.com with RSA key SHA256:ABh0UQvCU7k59+BS8DZ54r0q2GzeaOR0uuT0axOqYZ8
Author: Insaf Garifullin <jakefish.work@gmail.com>
Date:   Mon Sep 21 11:46:15 2026 +0300

    test: first signed commit
```

Every commit on this branch reports `G` (good signature) from `git log --format='%G?'`:

```console
$ git log main..HEAD --format='%h %G? %an <%ae> %s'
4b586b6 G Insaf Garifullin <jakefish.work@gmail.com> feat(lab3): add gitleaks + pre-commit hooks
cda2b88 G Insaf Garifullin <jakefish.work@gmail.com> test: first signed commit
```

### Verified badge on GitHub

<https://github.com/jakefish18/DevSecOps-Intro/commit/cda2b888a925226d7829d8dde29ec3db4005705b>

**Status at the time of writing: signed locally, not yet Verified on GitHub.** The GitHub API reports:

```console
$ gh api repos/jakefish18/DevSecOps-Intro/commits/cda2b88 --jq '.commit.verification'
verified = false
reason   = unknown_key
author   = jakefish18        # the commit IS linked to my account
```

`unknown_key` is the remaining half of step 3.2: the key is registered on my account as an
*Authentication* key only, and GitHub treats the two roles as separate registrations. The signature
itself is good — `git log --show-signature` verifies it offline against `allowed_signers` — and the
commit is correctly attributed to `jakefish18` now that `user.email` is set. Adding the same key bytes
at Settings → SSH and GPG keys → New SSH key with **Key type: Signing Key** flips this to
`verified = true` for every already-pushed commit, because GitHub evaluates signatures at read time
against the keys currently on the account rather than storing a verdict at push time.

### What a forged author line buys an attacker here

`git commit --author="Insaf Garifullin <jakefish.work@gmail.com>"` is a flag anyone can pass; the
author line is free-text metadata that Git never checks. In *this* repository the concrete abuse is
narrow but real: this fork is where my graded work lives, and every lab from 4 onward adds security
tooling to it — a `.pre-commit-config.yaml` that runs remote code on my machine, Actions workflows,
Lab 8's cosign keys. Anyone with push access to a shared branch could add a commit that loosens
`.gitleaks.toml` or repoints a hook `rev:` at their own fork, and `git log` would show my name and my
address on it. I would have no technical basis to say it was not me, and neither would a grader —
which is precisely the **repudiation** ("R" in STRIDE) risk my Lab 2 model raised around the
`admin-action-log` data asset.

The signature changes who can make that claim rather than who can make that commit. The SSH signature
covers the commit object — tree, parents, author, committer, message — with a private key that never
leaves my laptop, so a forged author line now produces an *unsigned* commit sitting next to signed
ones, and the difference is visible in `git log --show-signature` and as the missing Verified badge on
GitHub. It converts "trust the metadata" into "check the key", and it makes the absence of a signature
the anomaly worth investigating. What it does **not** do is prove intent or protect the key: anyone who
reads `~/.ssh/github` signs as me, which is why that file being passphrase-less is a real trade-off I
made for `commit.gpgsign = true` not prompting on every commit.

## Task 2

### `.pre-commit-config.yaml`

```yaml
exclude: |
  (?x)^(
    labs/lab6/vulnerable-iac/.*
  )$

repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks
        name: Detect hardcoded secrets

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ["--maxkb=1024"]
```

Both `rev:` values are real tags (`v8.30.1` is the current gitleaks release; `v6.0.0` is the current
`pre-commit-hooks` tag) and both are pinned. An unpinned `rev` is remote code that can change between
one commit and the next, and it executes on my machine — the same supply-chain argument Lab 2's
`container-baseimage-backdooring` finding makes about base images.

The `exclude` was not in the plan; `pre-commit run --all-files` forced it. `detect-private-key` fails
on `labs/lab6/vulnerable-iac/ansible/configure.yml`, which is a deliberately vulnerable teaching
fixture that *ships in the course repo* and is supposed to contain a key. Without the exclusion the
whole repository is un-committable. I also dropped `end-of-file-fixer`, `trailing-whitespace` and
`check-yaml` from a first draft after `--all-files` showed them rewriting ten upstream course files
that are not mine to reformat — a hook that edits other people's files by default is a hook that will
get disabled with `--no-verify`, which is worse than not having it.

```console
$ pre-commit run --all-files
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Passed
check for added large files..............................................Passed
```

### The blocked commit

```console
$ printf 'GH_PAT=ghp_16C7e42F292c6912E7710c838347Ae178B4a\n' > submissions/leak-attempt.txt
$ git add submissions/leak-attempt.txt
$ git commit -m "test: should be blocked"
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1

11:47AM INF 0 commits scanned.
11:47AM INF scanned ~48 bytes (48 bytes) in 15.2ms
11:47AM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
```

The rule is **`github-pat`**, and the shell reported exit code 1.

Proof nothing was committed — `HEAD` is still the previous commit:

```console
$ git log --oneline -1
4b586b6 feat(lab3): add gitleaks + pre-commit hooks
```

Note `0 commits scanned`: the hook runs gitleaks in staged-file mode, against the index, before a
commit object exists. That is the difference between this and a CI scan — there is nothing to purge
afterwards because nothing was ever written.

Cleanup: `git restore --staged submissions/leak-attempt.txt && rm submissions/leak-attempt.txt`.

### The hook then blocked this report, which is the interesting part

Committing `submissions/lab3.md` failed. The hook fired twice on my own write-up: once for
`github-pat` on line 148, because the report quotes the lab's fake `ghp_16C7...` token verbatim, and
once for `generic-api-key` on line 43, on the SHA256 fingerprint of my **public** signing key. Neither
is a credential — the first is published in `labs/lab3.md` itself, the second is public by definition —
but gitleaks is pattern matching, not reading, and both look exactly like the real thing.

So the choice from the section below arrived for real, and I took the value-scoped option. `.gitleaks.toml`:

```toml
[extend]
useDefault = true

[[allowlists]]
description = "Fake GitHub PATs published in labs/lab3.md itself, quoted verbatim in the Lab 3 report"
regexTarget = "match"
regexes = [
  '''ghp_16C7e42F292c6912E7710c838347Ae178B4a''',
  '''ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJ''',
]

[[allowlists]]
description = "SHA256 fingerprint of my PUBLIC SSH signing key - public by definition, not a credential"
regexTarget = "match"
regexes = [
  '''ABh0UQvCU7k59\+BS8DZ54r0q2GzeaOR0uuT0axOqYZ8''',
]
```

The tempting alternative was one line — `paths = ["submissions/"]` — and it would have worked
immediately. It would also have turned the directory holding every future lab report into a
scan-free zone, which is the exact failure mode I argue against below, so I would rather carry three
literals.

I checked that the exemption is as narrow as I claim, instead of assuming it:

```console
$ gitleaks dir other-token.txt --config .gitleaks.toml   # a ghp_ token differing in one character
WRN leaks found: 1
$ gitleaks dir lab-token.txt   --config .gitleaks.toml   # the exact literal from labs/lab3.md
INF no leaks found
```

One character different in the token and the rule fires again. That is what "allowlist the value, not
the shape" buys, and it is checkable in two commands.

### Tuning out `AKIA...` documentation examples

**Option A — an `[[rules.allowlist]]` / `[allowlist]` entry in `.gitleaks.toml`.** This is the precise
instrument: allowlist the *specific literal* (`AKIAIOSFODNN7EXAMPLE`) or a regex tight enough to match
only AWS's published example identifiers, and gitleaks keeps scanning every other string in the file,
including the next line. Scope stays with the value rather than the location, so the exemption travels
correctly when the example moves between files, and a reviewer reading `.gitleaks.toml` sees exactly
what was excused and can judge it. **It stops being safe the moment the pattern is loosened from a
literal to something shaped like a class** — an allowlist of `AKIA[A-Z0-9]{16}` or a blanket
`regexes = ['''AKIA.*''']` no longer exempts an example, it disables the AWS rule repository-wide, and
the real key that gets pasted next month matches it just as happily. The failure is silent: gitleaks
exits 0 and reports nothing.

**Option B — a path exclusion for `docs/`.** This is the blunt instrument: cheap, one line, obvious in
review, and reasonable when `docs/` is genuinely prose that no build step reads. But it exempts the
*location*, not the value, so it protects nothing about what is actually in there — it says "do not
look here" rather than "this string is fine". **It stops being safe as soon as `docs/` stops being only
prose**, which happens quietly and almost always: someone adds `docs/examples/` with a runnable
`docker-compose.yml`, or a `docs/deploy/` runbook with a real staging token, or the site generator
starts pulling `docs/config/` into a build. Nobody revisits the exclusion when that happens, because
the exclusion is in `.pre-commit-config.yaml` and the change is in `docs/`. The blind spot then grows
on its own, and a directory that is exempt from secret scanning is exactly where a hurried engineer
will put the thing they did not want scanned.

In short: the allowlist is safe while it names values and unsafe when it names shapes; the path
exclusion is safe while the path stays boring and unsafe the moment it does not — and nothing warns you
when it stops.

## Bonus

The sandbox is a throwaway repo outside the fork. One deviation: its commits were created with
`--no-gpg-sign`, because `commit.gpgsign` is now global and signatures would be discarded by the
rewrite anyway.

### `git log --oneline` before and after

```console
$ git log --oneline          # BEFORE
530eb52 docs: usage notes
d65e2c7 feat: empty log
c35a9e4 feat: add config
cc60781 init

$ git log --oneline          # AFTER
7ff5b13 docs: usage notes
0ed563a feat: empty log
e72f689 feat: add config
cc60781 init
```

### The three grep counts

```console
$ git log -p | grep -c 'ghp_AAAA'    # before rewrite
2
$ git log -p | grep -c 'ghp_AAAA'    # after rewrite
0
$ git log -p | grep -c 'REDACTED'    # after rewrite
2
```

2 → 0 for the secret, and 2 for the marker: both occurrences (`config.txt` and `README.md`) were
replaced, not just the one in the tip commit.

### The refusal, and what I did about it

```
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```

The parenthetical is the actual test, and it explains why a repo created thirty seconds earlier with
`git init` still fails: filter-repo does not look for a remote, it counts entries in the reflog for
`HEAD`. Four commits meant four reflog entries, so the check tripped. The refusal exists because
filter-repo's rewrite is not recoverable from within the repo — it strips the original refs and the
reflog it would need to undo itself — so it insists on a fresh clone, where the real history still
exists somewhere else to fall back on. In a throwaway sandbox that safety net is redundant, so `--force`
is the documented answer and the one I used:

```bash
git filter-repo --replace-text /path/to/replace.txt --force
```

### Rewriting history is step one. The step that ends the incident is **rotating the credential**.

The rewrite changes what my copy of the repository *says*; it does nothing to what the token *is*. From
the moment that secret was pushed, it existed outside my control: in every clone and fork, in the
GitHub API's dangling-commit views (an unreferenced commit stays fetchable by SHA long after the rewrite),
in CI logs and caches, in editor backups, and in the crawlers that watch the public push firehose and
grab `ghp_` strings within seconds. A rewrite cannot reach any of those. Until the credential is revoked
and reissued at the provider, the attacker's copy still authenticates — and the rewrite has actively made
things worse in one respect, because the evidence of what leaked is now harder to find in my own history.
The correct order is: **rotate first, then rewrite, then force-push and tell everyone to re-clone**, because
rotation is the only step that takes power away from whoever already has the value.

### Two things that surprised me

**1. A commit that never contained the secret still changed its hash — but the root commit did not.**
`feat: empty log` (`d65e2c7` → `0ed563a`) only ever added `app.log`. It was rewritten anyway, because a
commit hash covers its parent's hash, so rewriting `feat: add config` forces every descendant to change
whether or not its own content did. Meanwhile `init` kept `cc60781` across the rewrite, because it is
*before* the first modified commit and nothing it references moved. I expected "rewrite history" to mean
"all new SHAs"; it is precisely the suffix from the first changed commit onward, which is also why
everyone else's outstanding branches break and why the whole team has to re-clone.

**2. `git filter-repo` deleted my `origin` remote, and said nothing about it.** I tested this on purpose
rather than taking the lab's word for it: I copied the sandbox, added
`origin git@github.com:example/throwaway.git`, re-ran the rewrite, and `git remote -v` came back empty
with no warning in the output. It is deliberate — filter-repo removes the remote so a reflexive
`git push` cannot quietly send rewritten history somewhere, and forces you to re-add it consciously —
but a destructive side effect announced nowhere in the success message is a genuinely surprising default.
It also means the "re-add the remote and force-push" step at the end of a real cleanup is not optional
tidying; without it there is nothing to push to.
