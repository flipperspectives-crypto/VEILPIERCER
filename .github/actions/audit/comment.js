const fs = require('fs');
const path = require('path');
const findingsDir = '/tmp/findings';

if (!fs.existsSync(findingsDir)) {
  console.log('No findings directory');
  return;
}

const files = fs.readdirSync(findingsDir).filter(f => f.endsWith('.json'));
if (files.length === 0) {
  console.log('No findings');
  return;
}

let body = '## 🔍 VeilPiercer Audit Findings\n\n';
body += '| File | Severity | Vulnerability | Lines |\n';
body += '|------|----------|--------------|-------|\n';

let total = 0;
for (const f of files) {
  const data = JSON.parse(fs.readFileSync(path.join(findingsDir, f)));
  for (const finding of data.findings || []) {
    total++;
    const sev = finding.severity.toUpperCase();
    const emoji = sev === 'CRITICAL' ? '🔴' : sev === 'HIGH' ? '🟠' : '🟡';
    body += `| ${data.file} | ${emoji} ${sev} | ${finding.vulnerability} | ${finding.lines.join(', ')} |\n`;
  }
}

body += `\n---\n*${total} finding(s) by [VeilPiercer](https://github.com/flipperspectives-crypto/VEILPIERCER). [Try the demo](https://3924739b617b797e-65-94-86-110.serveousercontent.com). Automated scan — review manually.*`;

await github.rest.issues.createComment({
  owner: context.repo.owner,
  repo: context.repo.repo,
  issue_number: context.issue.number,
  body
});
