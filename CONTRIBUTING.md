
<div align="center">

<img src="Nazlabadi-original-logo.jpg" alt="Nazlabadi" width="96">

# Contributing to HookScope

### Inspect safely. Build carefully. Verify everything.

**Offline-first · Security-focused · Evidence-driven**

Thank you for helping improve HookScope.

A Python startup-artifact inspection tool built around safe static analysis, reproducible findings, and deliberate security boundaries.

[Project Home](README.md) · [Security Policy](SECURITY.md) · [Documentation](docs/QUICKSTART.md)

</div>

---

## 01 — Welcome

Great software is built through careful contributions.

Whether you're fixing a parser, adding a regression test, improving documentation, or investigating unexpected behavior, your work is welcome.

We value three things above all:

| Principle | What it means |
|:---|:---|
| **Safety first** | Never execute untrusted inspected content |
| **Evidence matters** | Every bug should be reproducible |
| **Clarity wins** | Small, readable changes beat unnecessary complexity |

---

## 02 — What Can You Contribute?

- **Detection & parsing** — Improve recognition of Python startup artifacts, including `.pth` files and `sitecustomize.py`.
- **Reliability** — Resolve parsing discrepancies and edge cases.
- **Testing** — Add deterministic regression tests and synthetic fixtures.
- **Reports** — Improve output consistency and schema correctness.
- **Documentation** — Clarify usage, limitations, and supported environments.

> **Design boundary:** HookScope inspects artifacts without importing or executing the inspected Python code.

---

## 03 — Report an Issue

A useful bug report makes the problem easy to reproduce.

Please include:

| Information | Description |
|:---|:---|
| Python version | Exact interpreter version |
| Operating system | OS and relevant environment |
| Command | Complete command used |
| Fixture | Minimal, non-malicious sample |
| Expected behavior | What should have happened |
| Actual behavior | What happened instead |

<details>
<summary><b>View example bug report</b></summary>

### Reproduction template

    Title: Unexpected .pth parsing result

    Environment:
      Python: 3.13
      OS: Linux

    Command:
      [Exact reproduction command]

    Input:
      [Minimal synthetic fixture]

    Expected:
      [Expected result]

    Actual:
      [Observed result]

    Notes:
      [Additional relevant information]

Do not include real credentials or sensitive system data.

</details>

---

## 04 — Development Workflow

### Step 1 · Prepare your environment

Clone the repository and enter the project directory.

```bash
git clone https://github.com/moalinazli/HookScope.git
cd HookScope
```

For the documented verified Linux path, use Python 3.13.

### Step 2 · Make focused changes

Keep changes minimal, understandable, and relevant to the reported issue.

Do not introduce unnecessary dependencies or network requirements.

### Step 3 · Run the tests

Before submitting a pull request:

```bash
python -m unittest discover -s tests -v
```

Fix any regression introduced by your changes.

### Step 4 · Verify compatibility

When changing an output structure:

- Update `schema_version`.
- Update the corresponding tests.
- Document compatibility implications.
- Preserve predictable error handling.

---

## 05 — Parser Safety Requirements

<details open>
<summary><b>Core security boundaries</b></summary>

All new parsers must:

- [ ] Run offline.
- [ ] Never import inspected code.
- [ ] Never execute inspected content.
- [ ] Handle malformed or unexpected input safely.
- [ ] Include appropriate positive and negative tests.
- [ ] Use deterministic synthetic fixtures.
- [ ] Preserve established security boundaries.

**Treat every inspected artifact as untrusted input.**

</details>

<details>
<summary><b>Output integrity and compatibility</b></summary>

Changes affecting JSON, SARIF, HTML, or other report structures should be reviewed for compatibility.

Update `schema_version` and tests whenever the output structure changes.

A report should distinguish observations from conclusions. A suspicious artifact is an investigation lead, not automatic proof of compromise.

</details>

---

## 06 — Security & Responsible Contributions

Please do not submit:

- Real credentials, passwords, tokens, or API keys.
- Live malicious payloads.
- Sensitive or confidential production data.
- Proprietary third-party source code.
- Material that violates upstream licensing requirements.

Use safe, minimal, synthetic fixtures.

Preserve original licenses, copyright notices, and citations when reusing third-party material.

For sensitive security reports, follow the project's [Security Policy](SECURITY.md).

---

## 07 — Pull Request Checklist

Before opening a pull request:

- [ ] My contribution has a clear purpose.
- [ ] The change is focused and understandable.
- [ ] I have run the full unit test suite.
- [ ] New behavior has appropriate tests.
- [ ] Parsers remain offline and non-executing.
- [ ] Relevant schema changes are versioned.
- [ ] No secrets or unsafe test material are included.
- [ ] Third-party licensing obligations are respected.
- [ ] Documentation is updated where necessary.

---

## 08 — Engineering Philosophy

<div align="center">

### LESS MAGIC. MORE EVIDENCE.

**Readable code. Predictable behavior. Reproducible results.**

Security is not a visual feature.

It is a property that must survive testing, review, and unexpected input.

</div>

---

## 09 — Thank You

A contribution does not have to be large to be valuable.

One well-documented bug, one carefully designed test, or one reliable fix can make a meaningful difference.

Thank you for making HookScope better.

---

<div align="center">

**HOOKSCOPE**

*Inspect what loads. Understand what matters.*

**NAZLABADI**

</div>
