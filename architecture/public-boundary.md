# Public Boundary

This repo is allowed to contain public-safe architecture, contracts, and local-only scaffolding. It should not contain operational details that would expose the real rack, accounts, or agent workloads.

## Safe to Commit

- Abstract component names: `control-plane`, `worker-group-a`, `review-queue`.
- Abstract capability names: `routing`, `automation`, `siem`, `edr`, `logging`, `scheduler`, `worker-capacity`.
- Local-only defaults: `127.0.0.1`, `localhost`, `test` AWS credentials for LocalStack.
- Topic names, message envelopes, local resource names, and placeholder policies.
- Sanitized examples that do not reveal customer data, private prompts, model secrets, rack addresses, serial numbers, or exact deployment topology.
- Failure-mode documentation written at the architectural level.

## Keep Private

- Paperclip API keys, production endpoints, prompt libraries, workflow secrets, or account identifiers.
- AWS account IDs, access keys, real ARNs, Terraform state, and production IAM policy bindings.
- Rack hostnames, private IPs, public IPs, MAC addresses, serial numbers, IPMI/BMC details, switch configuration, physical port maps, storage controller details, and remote access procedures.
- OpenWrt exports, VLAN IDs, firewall rules, Kubernetes kubeconfigs, production manifests, SIEM/EDR console details, detection logic, and private incident records.
- Logs that contain secrets, private datasets, user data, internal run IDs, or unredacted model transcripts.

## Recommended Split

- Public repo: sanitized contracts, local compose files, test doubles, review process, and non-sensitive Rust interfaces.
- Private repo or encrypted store: deployment inventory, secrets, rack automation, real prompt packs, production policies, and vendor-specific operating procedures.

## Review Checklist

- No credentials or real endpoints.
- No rack topology that would help an outsider reach or fingerprint the system.
- No private model prompts or sensitive generated outputs.
- No exact operational runbooks for power, remote management, firmware, or storage recovery.
- Local examples work without real cloud or Paperclip access.

## Publication Checks

Run `python3 tools/check_public_boundary.py --tree HEAD` against the commit to
publish. It reads Git objects, so ignored files forced into a commit are checked
and private untracked working files are not read. It rejects local notes, runtime
state, key files, generated binaries, and personal workstation paths. The narrow
synthetic path exceptions are tied to their test files. Images still require a
human review against their fixture provenance.

Before publication, also pass `--since <already-public-commit-id>` to check every
introduced commit tree, including private files added and then deleted before the
tip. The baseline must come from the destination's old ref or a trusted CI event;
arbitrary local branches and tracking refs are not evidence of prior publication.
For new refs, `--public-remote <destination>` reads currently advertised branch
IDs and excludes only their ancestry. Missing objects, failed remote discovery,
and an empty public remote fail closed. Fetch the advertised commits first.

The `Public repository boundary` workflow also scans the committed tree and its
reachable history using checksum-pinned Gitleaks. Its configuration retains the
default rules with two exact, file-specific exceptions for known test/prose false
positives. `.gitleaksignore` files are rejected and scanner suppression files and
inline allow comments are disabled. Neither matching secret values nor runtime
reports are uploaded. CI uses the push event's previous commit or the pull
request's base commit, never the branch's already-updated remote tip. A new-branch
push has no previous commit and fails closed: use a manual workflow run with a
reviewed already-public commit ID. Initial publication to an empty remote needs
separate full-history review; this workflow cannot infer a safe bootstrap base.

For protection before a Git push, install Gitleaks 8.30.1, set `GITLEAKS_BIN` to
the executable (or place it at `.athernex/tools/gitleaks`), then enable the checked-in
hook with `git config --local core.hooksPath .githooks`. Review any existing hook
configuration before replacing it. The hook fails closed if the scanner is missing.
Git hosting APIs bypass local hooks, so API publication must perform these checks
against the exact outgoing tree before uploading any objects. CI runs after upload
and cannot prevent an initial disclosure. These checks supplement human review;
they cannot determine whether every arbitrary document contains private information.
