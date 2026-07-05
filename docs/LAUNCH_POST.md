# VeilPiercer — Free Multi-Engine Smart Contract Audits

I built a free smart contract audit tool that scans Solidity code with 3 detection engines in seconds. No API keys. No cloud. MIT licensed.

🔗 **Try it:** https://3924739b617b797e-65-94-86-110.serveousercontent.com

## What it does

Paste any Solidity contract. Get an instant report with:
- **3 engines**: regex pattern scanner (69% recall), Slither (22% recall / 19% FP), Mythril (symbolic execution)
- **Severity scoring**: critical / high / medium / low / informational
- **Cryptographic proofs**: SIAS-anchored timestamps — prove when you found a vulnerability
- **Verified badge**: protocols passing thresholds get a README badge

## How good is it?

Published confusion matrix — no marketing, just numbers:
- 225 contracts benchmarked
- 579 findings across 39 contest categories
- 96.2% dependency resolution rate
- 69% recall on regex scanner, 94% FP rate (we tell you what we miss)

See the full benchmark: https://github.com/flipperspectives-crypto/VEILPIERCER/blob/main/docs/benchmark-report-v2.2.md

## Try these in 1 click

Open the demo and click any button:
- 🔁 Reentrancy
- ⚡ Flash Loan manipulation  
- 🔐 Missing access control
- 📊 Oracle price manipulation

Each scans in under 1 second.

## Get your protocol verified

Paste your contract at /verify → get a `[![VeilPiercer Verified](...)]` badge for your README.

## Contribute

5 good-first-issues open. Add a detection pattern, run the benchmark, submit a PR:
https://github.com/flipperspectives-crypto/VEILPIERCER/issues/1

No Solidity PhD needed — the CONTRIBUTING.md walks you through it with a worked example.

## Free to host yourself

```bash
docker compose up -d       # Docker
fly deploy                  # Fly.io (free tier)
ssh -R 80:localhost:9100 serveo.net  # SSH tunnel (zero install)
```

6 deploy options in DEPLOY.md.

---

Feedback? Scan a contract and tell me what it found (or missed). The confusion matrix improves with every real test.
