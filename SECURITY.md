# Security

HookScope is an **offline static auditor**, not a sandbox, antivirus, EDR, or live-monitoring agent.

Use a trusted interpreter and a read-only mounted snapshot. Do not run Python from a suspected compromised environment simply to learn its startup paths: interpreter initialization may execute the artifact under investigation.

HookScope does not download samples, contact external services, install wheels, or execute inspected source code. It never modifies inspected inputs. The optional report destination must be outside the scanned snapshot.

Protect output reports because filesystem paths, package names, module names, hashes and optionally raw startup statements may be sensitive.

For vulnerability reports about this project, use a private GitHub security advisory instead of a public issue when the report includes an exploitable security defect.
