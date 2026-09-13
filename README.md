# policy-as-code

Synthetic reference. Not a client repository, not an audit conclusion, and not a certification.

Three OPA policies and `opa test` data. A git rule fails a command when the input is wrong. A PDF pack does not.

License: MIT. See [LICENSE](LICENSE).

## What this is

| Policy | Control label | Passes when |
| --- | --- | --- |
| `policies/storage` | CC6.1 encryption | every object uses SSE-KMS (`aws:kms`) |
| `policies/iam` | CC6.3 access | no statement sets `Action` or `Resource` to `*` |
| `policies/change` | CC8.1 exception | an out-of-window change has a reason and an unexpired `YYYY-MM-DD` expiry |

Inputs are synthetic. Object name is `synthetic-object`. There is no customer bucket, no cloud account, and no Conftest daemon.

A control id here is a filing label so an assessor can match an artifact to a row. A passing test does not mean a Trust Services Criterion is met.

On this repository, `opa-test` is required to merge into `main`. Repository admins can bypass the ruleset to ship a reference fix. The same job runs on every push and pull request.

## What this is not

- Not a policy PDF. The PDF describes an intent. This file denies a specific input, and `opa test` shows the deny message.
- Not Conftest, and not a live cloud evaluation.
- Not a client control set.

## Run the tests

Install the `opa` CLI (this sample was checked with 1.20.2). No daemon.

```bash
opa test . -v
```

A deny case is a passing test: the test expects the deny message. `opa test` exits 0 when those expectations hold. On opa 1.20, `opa test .` walks the tree. The Go-style path `./...` is not a file this CLI accepts.

To see a deny on one input:

```bash
opa eval --data policies/iam --input <(printf '%s' '{"statements":[{"Sid":"TooWide","Action":"*","Resource":"*"}]}') 'data.iam.wildcard.deny'
```

The message names the control (`CC6.3 access`). Missing reason and an expired date are covered in `policies/change/exception_test.rego`.

## How a git rule differs from a PDF pack

A PDF says “least privilege” and an assessor has to trust the sentence. This repo says the same idea as a rule that fails when `Action` is `*`. The artifact is the policy path plus the test output, not a signed PDF of the policy.

## Companion repos

The CI gates fail a pull request. This repo is the rule those gates can call. The evidence index points a control id at a path in each.

- [ci-security-gates](https://github.com/yellow-theme/ci-security-gates)
- [policy-as-code](https://github.com/yellow-theme/policy-as-code)
- [evidence-index](https://github.com/yellow-theme/evidence-index)
