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
