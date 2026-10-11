# Lab 9 — Runtime Detection and Policy as Code

Tooling: Falco 0.43.1 (modern eBPF), Conftest dev (OPA 1.21.1), on a Colima VM
(`--vm-type vz`, Virtualization.framework, aarch64) because Docker Desktop's VM does not expose the
host kernel. Target: `alpine:3.20`.

Two environment notes, both consistent with the lab's own warnings:

- Falco logs `failure while attaching TOCTOU mitigation program` and `failed to create tracepoint
  syscalls/sys_enter_open` at startup. This is the missing-tracepoint case the lab calls out for WSL2.
  Detection still works: the open-family rules below (`open_read`, `open_write`) all fire.
- The same kernel does not populate the socket tuple on `connect` events: `fd.name` comes back
  `0.0.0.0:0` and `fd.sport` is `null` for every outbound connection (shown in the Bonus). That shapes
  how the mining rule had to be written and triggered, and I document it there rather than hiding it.

## Task 1

### 9.2 — the two built-in rules

```console
$ docker exec -t lab9-target sh -lc 'echo hello-from-shell'
$ docker exec    lab9-target sh -c  'cat /etc/shadow'
$ docker logs falco | grep -o '"rule":"[^"]*"' | sort | uniq -c
   1 "rule":"Read sensitive file untrusted"
   1 "rule":"Terminal shell in container"
```

**`Terminal shell in container`** (priority Notice) fired on the first command:

```json
{"rule":"Terminal shell in container","priority":"Notice",
 "proc.cmdline":"sh -lc echo hello-from-shell","proc.tty":34816,"container.name":"lab9-target"}
```

Trigger: a shell started inside the container **with a TTY attached** (`proc.tty` is non-zero, 34816).
The `-t` flag is what makes this fire; a plain `docker exec` has no TTY and the rule keys on one.

**`Read sensitive file untrusted`** (priority Warning) fired on the second:

```json
{"rule":"Read sensitive file untrusted","priority":"Warning",
 "fd.name":"/etc/shadow","proc.cmdline":"cat /etc/shadow","container.name":"lab9-target"}
```

Trigger: a process opened `/etc/shadow` for reading, a path on Falco's sensitive-file list, from a
program (`cat`) not on the trusted reader allowlist.

### 9.3 — a rule the defaults do not have

`labs/lab9/falco/rules/custom-rules.yaml` (the `Write to /tmp in a container` rule):

```yaml
- rule: Write to /tmp in a container
  desc: A file under /tmp was opened for writing from inside a container.
  condition: >
    open_write
    and container.id != "host"
    and fd.name startswith /tmp/
  output: >
    Write under /tmp in container
    (container=%container.name image=%container.image.repository
     user=%user.name uid=%user.uid file=%fd.name
     proc=%proc.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

After `docker kill --signal=SIGHUP falco` and `docker exec --user 0 lab9-target sh -lc 'echo test >
/tmp/my-write.txt'`, it fired:

```json
{
  "rule": "Write to /tmp in a container",
  "priority": "Warning",
  "output_fields": {
    "container.id": "4c67d9fd355e",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1791723864960564823,
    "fd.name": "/tmp/my-write.txt",
    "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
    "proc.name": "sh",
    "user.name": "root",
    "user.uid": 0
  },
  "tags": ["container", "drift"]
}
```

### One JSON field that matters in an incident but is not in the message I wrote

`container.id` (`4c67d9fd355e`). My `output` sentence names the container by `%container.name`
(`lab9-target`), which is a human label: it is chosen by whoever launched the container and can be reused
across restarts or deliberately set to look innocuous. The structured `container.id` in `output_fields`
is the immutable handle for the exact running instance, and it is what you actually pivot on during
response: `docker kill 4c67d9fd355e`, or a query that isolates that one container's events out of
thousands. A responder reading only the prose has the name; the tooling consuming `output_fields` has the
ID.

### The /tmp rule is noisy: a legitimate flag and how to keep the signal

The rule fires on every `/tmp` write in every container, and plenty of healthy workloads write there
constantly: a JVM writes `/tmp/hsperfdata_*` on startup, Python and Node extract packages into `/tmp`,
and any app using `tempfile` or building in `/tmp` trips it on every run. Juice Shop itself, under the
Lab 7 read-only-root deployment, mounts an emptyDir at `/tmp` precisely so it can write scratch there.
The way to keep the detection without the noise is to make the condition narrower than "any write": add
an exception list of expected writers by process name or image for the known-good cases (`and not
proc.name in (java, python3, node)`), or invert the logic so the rule keys on *executable* files
appearing in `/tmp` (`fd.name` plus the file later being opened for exec) rather than any write, since a
staged payload is interesting when it runs, not when it lands. The principle is to tighten the condition
toward the attacker behaviour, not to silence the rule or raise its threshold.

## Task 2

### 9.4 — counts, and failures mapped to rules

```console
$ conftest test .../k8s/juice-hardened.yaml   --policy labs/lab9/policies --all-namespaces
30 tests, 30 passed, 0 warnings, 0 failures
$ conftest test .../k8s/juice-unhardened.yaml --policy labs/lab9/policies --all-namespaces
30 tests, 20 passed, 2 warnings, 8 failures
$ conftest test .../compose/juice-compose.yml --policy labs/lab9/policies --all-namespaces
15 tests, 15 passed, 0 warnings, 0 failures
```

| Manifest | Passed | Warnings | Failures |
|---|---:|---:|---:|
| `juice-hardened.yaml` | 30 | 0 | 0 |
| `juice-unhardened.yaml` | 20 | 2 | 8 |
| `juice-compose.yml` | 15 | 0 | 0 |

The 8 failures on the unhardened manifest, each mapped to its rule in `k8s-security.rego`:

| Failure message | Rego rule |
|---|---|
| uses disallowed `:latest` tag | the `endswith(c.image, ":latest")` deny |
| must set `runAsNonRoot: true` | `not c.securityContext.runAsNonRoot` deny |
| must set `allowPrivilegeEscalation: false` | `not c.securityContext.allowPrivilegeEscalation == false` deny |
| must set `readOnlyRootFilesystem: true` | `not c.securityContext.readOnlyRootFilesystem == true` deny |
| missing `resources.requests.cpu` | `not c.resources.requests.cpu` deny |
| missing `resources.requests.memory` | `not c.resources.requests.memory` deny |
| missing `resources.limits.cpu` | `not c.resources.limits.cpu` deny |
| missing `resources.limits.memory` | `not c.resources.limits.memory` deny |

The two warnings map to the `readinessProbe` and `livenessProbe` warn rules. (The shipped
"drop ALL capabilities" deny does not appear: with no `securityContext` at all on the unhardened
container, the `has_value(c.securityContext.capabilities.drop, ...)` call takes an undefined argument,
so that single rule evaluates to undefined rather than firing. 8 failures, matching the lab.)

### Why Compose needs its own rule, and what its passing tells you

The same requirement needs a separate rule per format because the field paths are completely different:
"drop all capabilities" is `input.spec.template.spec.containers[_].securityContext.capabilities.drop` in
a Kubernetes Deployment and `input.services[_].cap_drop` in Compose, so `k8s-security.rego` walking the
pod template would find nothing in a Compose file and vice versa. The Compose file passing all 15 checks
is the control group the lab asks for: a policy set that only ever reports failures could be failing for
a bug in the policy rather than a flaw in the manifest. The hardened Compose file sets `user`,
`read_only`, `cap_drop: [ALL]` and `no-new-privileges`, so its green result confirms the Compose rules
can distinguish a good manifest from a bad one, which is what makes the Kubernetes failures trustworthy.

### 9.5 — two checks the shipped policy misses

`labs/lab9/policies/extra/hardening.rego`:

```rego
package k8s.security.extra

# deny: images must be pinned by digest, not a mutable tag. The shipped policy only
# bans :latest, so bkimminich/juice-shop:v20.0.0 slips past it even though a tag can
# be re-pointed at different content (the Lab 8 swap attack).
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q must pin its image by digest, not a tag (%s)", [c.name, c.image])
}

# warn: a memory limit above 1Gi lets one pod reserve an outsized slice of a node.
# The shipped policy checks that a limit EXISTS; it never checks its magnitude.
warn contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  limit := c.resources.limits.memory
  units.parse_bytes(limit) > units.parse_bytes("1Gi")
  msg := sprintf("container %q memory limit %s exceeds the 1Gi ceiling", [c.name, limit])
}
```

Both pass the hardened manifest (digest-pinned image, 512Mi limit) and both fire on a manifest I wrote to
violate them, `/tmp/violates-my-policy.yaml`, which is otherwise fully hardened so the shipped rules all
pass and only mine fire:

```console
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
34 tests, 34 passed, 0 warnings, 0 failures

$ conftest test /tmp/violates-my-policy.yaml --policy labs/lab9/policies --all-namespaces
WARN - k8s.security.extra - container "juice" memory limit 4Gi exceeds the 1Gi ceiling
FAIL - k8s.security.extra - container "juice" must pin its image by digest, not a tag (bkimminich/juice-shop:v20.0.0)
17 tests, 15 passed, 1 warning, 1 failure
```

The violating manifest uses `image: bkimminich/juice-shop:v20.0.0` (a tag, so the shipped `:latest`
rule stays quiet but my digest rule fires) and `limits.memory: 4Gi` (my ceiling warn fires); everything
else is hardened, so the 15 shipped checks still pass.

### CI rule or runtime rule: which one I keep

For the digest-pinning control, I keep the **Conftest rule in CI**. A manifest that pins by tag is a
defect you want to stop *before* it ships, and CI is the only place you can refuse it outright: the fix
is to edit one line and re-run, with no production impact. Falco cannot enforce this at all in the same
way, because by the time a container is running the image is already resolved to a digest. What the
runtime side still buys you is the case CI cannot see: Conftest only checks the manifests that go through
your pipeline, so it is blind to a pod someone applies by hand, a workload from another team's repo, or a
container a compromise starts directly on the node. Falco watches the kernel regardless of how the
workload got there. So the one I keep is the preventive CI gate; the one I give up still mattered for
coverage of everything that never passed through CI.

## Bonus — catch a cryptominer

### The rule

```yaml
- rule: Outbound connection to mining pool from container
  desc: >
    A process inside a container opened an outbound connection that looks like it is
    reaching a mining pool: either a well-known pool port or a miner/raw-socket process name.
  condition: >
    evt.type = connect
    and container.id != "host"
    and (
      fd.sport in (3333, 4444, 5555, 7777, 14444)
      or proc.name in (xmrig, xmrig-proxy, minerd, cpuminer, xmr-stak, nc, ncat, socat)
    )
  output: >
    Outbound connection resembling mining-pool traffic from container
    (container=%container.name image=%container.image.repository
     proc=%proc.name cmdline=%proc.cmdline
     connection=%fd.name server_port=%fd.sport user=%user.name)
  priority: CRITICAL
  tags: [container, network, mitre_command_and_control, T1496]
```

It combines two signals gated by a third: an outbound `connect` (the network signal), from inside a
container (the context gate), where **either** the destination is a classic pool port **or** the process
is a miner / raw-socket tool miners use to reach a pool (the identity signal). Requiring the
container-egress gate plus one of the pool signals is what separates it from a rule that alerts on all
network traffic.

### The alert it produced

```console
$ docker exec lab9-target sh -c 'nc -w 2 127.0.0.1 3333'   # refused, nothing is listening
$ docker logs falco | grep -c '"priority":"Critical"'
1
```

```json
{"rule":"Outbound connection to mining pool from container","priority":"Critical",
 "tags":["T1496","container","mitre_command_and_control","network"],
 "output_fields":{"container.name":"lab9-target","proc.name":"nc",
   "proc.cmdline":"nc -w 2 127.0.0.1 3333","fd.name":"0.0.0.0:0","fd.sport":null,"user.name":"root"}}
```

Honest note on *which* signal fired. The alert shows `fd.sport: null` and `fd.name: 0.0.0.0:0`: this
Colima vz kernel does not populate the socket tuple on `connect` (I confirmed it with a debug rule that
logged every connect, and `fd.sport` was always null, even for an established connection to a real
listener). So the pool-port branch cannot be evaluated here, and the alert fired through the
process-name branch, `nc` being a raw-socket tool on the list. On a fully instrumented kernel the
port branch is the primary trigger; here it is dark, which is itself a useful lesson about depending on
one field.

### Why a refused connection is enough, and what it says about where Falco sits

A refused connection still issues the `connect()` **system call** with the destination address as its
argument; the kernel only returns `ECONNREFUSED` after the call is made. Falco reads syscalls from the
kernel through eBPF, so it sees the attempt the moment the process makes it, before and regardless of
whether a packet is answered. That is the point of runtime detection at the kernel boundary: it observes
intent and behaviour (this process tried to reach a pool), not just completed network flows. A network
monitor watching for an established session to a pool would see nothing from a refused attempt; Falco
sees it because it sits below the network, at the syscall.

### An attacker reads the rule and picks another port

The port list is the **cheap** part to evade: pools accept connections on arbitrary ports, so an
attacker changes one number in their config and the `fd.sport in (3333, ...)` branch never matches
again. The behaviour is the **expensive** part: a miner has to open an outbound connection from inside
the container to reach a pool at all, so `evt.type = connect and container.id != "host"` is costly to
avoid, and running the binary under an innocuous process name is cheap but running it without any egress
is not (a miner that cannot reach a pool earns nothing). To catch the evasion I would stop enumerating
ports and key on the behaviour the attacker cannot drop: sustained outbound connections from a workload
whose baseline is no egress, combined with the process-level signal this kernel does give me (a spawned
binary from `/tmp` or a renamed executable), and CPU saturation. The detections that survive an attacker
reading your rules are the ones tied to what the attack must do, not to the specific values it happens to
use today.
