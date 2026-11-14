# Container Dependency Security Review

## Scope and Status

Status: Implemented review with unresolved findings.

This review covers the exported Prometheus, Loki, and Grafana images used
by the local Project 10 monitoring stack. Trivy reports, binary hashes,
Go build metadata, and govulncheck results were preserved separately.

The container audit has not established a vulnerability-free environment.

## Tested Hardening

Grafana is configured to disable plugin preinstallation and 16 unused
datasource plugins. The configured Prometheus and Loki plugins remain enabled.

Running-container configuration verification passed four checks.
Post-change dashboard validation passed 18 checks: unauthenticated data
query rejection, provisioning of all 16 panels, and each panel's queries.

Evidence: evidence/public/dashboard-plugin-hardening-validation-*.json.

These checks establish configuration and dashboard query behavior.
They do not establish vulnerability remediation or detection effectiveness.
Disabled plugins and their dependencies remain in the image.

## Findings Supported by Embedded Versions

| Component | Embedded dependency | Advisory | Review status |
|---|---|---|---|
| Grafana Prometheus plugin | golang.org/x/net v0.61.0 | GO-2026-6860 / CVE-2026-78661 | Affected version and matching symbols reported; runtime reachability unverified |
| Grafana Loki plugin | golang.org/x/net v0.60.0 | GO-2026-6860 / CVE-2026-78661 | Affected version and matching symbols reported; runtime reachability unverified |
| Grafana Loki plugin | github.com/klauspost/compress v1.20.0 | GO-2026-6865 / CVE-2026-116591 | Affected version and matching symbols reported; runtime reachability unverified |

GO-2026-6860 identifies a fix in golang.org/x/net v0.62.0.
GO-2026-6865 identifies a fix in github.com/klauspost/compress v1.20.2.

Other scanner findings remain subject to individual review. This table
is not an exhaustive vulnerability inventory.

## Version-Matching Limitations

Prometheus and promtool report a timestamped main-module pseudo-version
with a dirty marker. Grafana's main module reports "(devel)".

Release tags, embedded module versions, and advisory version ranges must
be reconciled before classifying ambiguous main-module findings.
Neither version ambiguity nor the absence of a finding in another
scanner establishes a false positive.

Binary symbol analysis does not establish runtime call-path reachability.

## Treatment and Residual Risk

Status: Proposed remediation for unresolved vendor dependencies.

Use vendor releases containing the relevant fixes, verify their embedded
versions, rescan the exact replacement images, and repeat configuration
and dashboard validation before marking findings remediated.

Current lab restrictions reduce exposure but do not eliminate the
vulnerabilities. This review does not record acceptance for production use.

Owner: Project owner.

Reassess when replacement vendor images become available, configuration
changes expose additional functionality, or advisory information changes.

## Primary References

- https://pkg.go.dev/vuln/GO-2026-6860
- https://pkg.go.dev/vuln/GO-2026-6865
- https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
