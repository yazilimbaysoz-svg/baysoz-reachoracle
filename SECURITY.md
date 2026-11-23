# Security Policy — Baysöz Labs <baysozlabs@proton.me>

**Project:** `baysoz-reachoracle` · **Version:** 1.0.0 · **Owner:** Baysöz Labs (`baysozlabs@proton.me`)

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Email **baysozlabs@proton.me** with a description, reproduction input, affected version and impact.
Do not open a public issue for an unpatched vulnerability. Baysöz Labs acknowledges reports within
3 business days and targets a fix or mitigation plan within 30 days for confirmed issues.

## Authorized use

This tool is a static analysis oracle for software you own or are explicitly authorized to assess.
It does not exploit targets: it reads SBOM/advisory/source text and emits reports. The adversarial
corpus contains inert source strings only; no payload is executed and no network request is made.

## Security design

- **Offline by construction:** no HTTP client, telemetry, subprocess execution, dynamic import of
  user code, or LLM invocation in the runtime path.
- **Single small dependency:** `packaging` for PEP 440/PEP 503 correctness; no service, database or
  heavy framework.
- **Input validation:** advisory ids, severity, dotted symbol paths, PEP 440 specifiers and SBOM
  component fields are validated before analysis; malformed input exits `2`.
- **No unsafe deserialization of inputs:** only `json.loads` is used; Python source is parsed with `ast`,
  never executed.
- **Fail-safe verdicts:** dynamic dispatch is `UNRESOLVED`, never a clean pass. Suppression baselines
  are keyed to stable, location-sensitive IDs.
- **Supply-chain hardened CI:** GitHub Actions pinned to full 40-character commit SHAs; quality gates
  run pytest, Ruff (`E,F,W,S,B`) and Semgrep (`p/default`, `--error`).

## Known limitations (see docs/ARCHITECTURE.md)

Static reachability is not a formal proof. Cross-module interprocedural flow, decorators, C extensions
and runtime code generation are outside the model. Treat `NOT_REACHED` as "no evidence found by this
oracle", not as a security guarantee; treat `UNRESOLVED` as requiring human review.

## Attribution

Baysöz Labs <baysozlabs@proton.me>
