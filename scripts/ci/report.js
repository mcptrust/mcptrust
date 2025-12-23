#!/usr/bin/env node
// CI Report Generator: converts check JSON to markdown
// Usage: node report.js <input.json> [--redact=bool] [--output=file]

const fs = require('fs');
const path = require('path');

function parseArgs(args) {
    const opts = { redact: true, output: null, input: null, stdin: false };
    for (const arg of args.slice(2)) {
        if (arg.startsWith('--redact=')) {
            opts.redact = arg.split('=')[1] !== 'false';
        } else if (arg.startsWith('--output=')) {
            opts.output = arg.split('=')[1];
        } else if (arg === '--stdin') {
            opts.stdin = true;
        } else if (!arg.startsWith('-')) {
            opts.input = arg;
        }
    }
    return opts;
}

function truncateHash(hash, redact = true) {
    if (!hash) return hash;
    if (!redact) return hash;
    if (hash.length <= 12) return hash;
    const colonIdx = hash.indexOf(':');
    if (colonIdx > 0 && colonIdx < 10) {
        const prefix = hash.slice(0, colonIdx + 1);
        const rest = hash.slice(colonIdx + 1);
        if (rest.length > 4) {
            return prefix + rest.slice(0, 4) + '…';
        }
    }
    return hash.slice(0, 12) + '…';
}

function scrubSecrets(msg) {
    if (!msg) return msg;
    const secretPatterns = [
        /\b[A-Za-z0-9_-]*(?:key|token|secret|password|api_key|apikey|auth)[A-Za-z0-9_-]*\s*[:=]\s*\S+/gi,
        /\bsk-[A-Za-z0-9-]{20,}/g,  // OpenAI-style keys (sk-..., sk-proj-...)
        /\bghp_[A-Za-z0-9]{36}/g,  // GitHub PATs
        /\bglpat-[A-Za-z0-9-]{20}/g, // GitLab PATs
        /\bgho_[A-Za-z0-9]{36}/g,  // GitHub OAuth tokens
        /\bghs_[A-Za-z0-9]{36}/g,  // GitHub server tokens
        /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, // Slack tokens
        /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, // JWTs
        /\bAKIA[A-Z0-9]{16}/g,     // AWS Access Key IDs
    ];
    let result = msg;
    for (const pattern of secretPatterns) {
        result = result.replace(pattern, '[REDACTED]');
    }
    return result;
}

function redactUri(uri, redact = true) {
    if (!uri) return uri;
    if (!redact) return uri;
    if (uri.includes('{') && uri.includes('}')) return uri;
    if (uri.startsWith('file://')) {
        // Keep scheme + first component
        const parts = uri.replace('file://', '').split('/');
        if (parts.length > 2) {
            return 'file:///' + parts[1] + '/…';
        }
    }
    return uri;
}

function groupBySeverity(drifts) {
    const groups = { CRITICAL: [], MODERATE: [], INFO: [] };
    for (const d of drifts || []) {
        const sev = (d.severity || 'INFO').toUpperCase();
        if (groups[sev]) {
            groups[sev].push(d);
        } else {
            groups.INFO.push(d);
        }
    }
    return groups;
}

function formatDriftItem(item, redact) {
    const id = redactUri(item.identifier, redact);
    let line = `- **${item.type}**: \`${id}\``;

    if (item.oldHash && item.newHash) {
        const oldH = truncateHash(item.oldHash, redact);
        const newH = truncateHash(item.newHash, redact);
        line += ` (\`${oldH}\` → \`${newH}\`)`;
    }

    if (item.message) {
        const msg = scrubSecrets(item.message);
        if (msg && msg !== '[REDACTED]' && !msg.match(/^\[REDACTED\]$/)) {
            line += `\n  - ${msg}`;
        }
    }

    return line;
}

function generateReport(checkResult, redact = true) {
    const lines = [];

    const icon = checkResult.outcome === 'PASS' ? '✅' : '❌';
    lines.push(`## ${icon} MCPTrust check: ${checkResult.outcome}`);
    lines.push('');

    lines.push(`- **Lockfile**: \`${checkResult.lockfile}\` (v${checkResult.lockfileVersion})`);
    if (checkResult.policy) {
        lines.push(`- **Policy**: \`${checkResult.policy.preset}\``);
    }
    lines.push(`- **Fail-on**: \`${checkResult.failOn}\``);
    lines.push('');

    const groups = groupBySeverity(checkResult.drift);

    if (groups.CRITICAL.length > 0) {
        lines.push(`### 🔴 CRITICAL (${groups.CRITICAL.length})`);
        for (const d of groups.CRITICAL) {
            lines.push(formatDriftItem(d, redact));
        }
        lines.push('');
    }

    if (groups.MODERATE.length > 0) {
        lines.push(`### 🟡 MODERATE (${groups.MODERATE.length})`);
        for (const d of groups.MODERATE) {
            lines.push(formatDriftItem(d, redact));
        }
        lines.push('');
    }

    if (groups.INFO.length > 0) {
        lines.push(`### ℹ️ INFO (${groups.INFO.length})`);
        for (const d of groups.INFO) {
            lines.push(formatDriftItem(d, redact));
        }
        lines.push('');
    }

    if ((checkResult.drift || []).length === 0) {
        lines.push('✅ No drift detected');
        lines.push('');
    }

    if (checkResult.policy) {
        const pIcon = checkResult.policy.passed ? '✅' : '❌';
        const pStatus = checkResult.policy.passed ? 'PASS' : 'DENY';
        lines.push(`### Policy: ${pIcon} ${pStatus}`);

        if (!checkResult.policy.passed && checkResult.policy.reasons) {
            for (const reason of checkResult.policy.reasons) {
                lines.push(`- ${reason}`);
            }
        }
        lines.push('');
    }

    lines.push('---');
    lines.push('_Generated by [MCPTrust](https://github.com/mcptrust/mcptrust)_');

    return lines.join('\n');
}

async function readStdin() {
    return new Promise((resolve, reject) => {
        let data = '';
        process.stdin.setEncoding('utf8');
        process.stdin.on('data', chunk => { data += chunk; });
        process.stdin.on('end', () => resolve(data));
        process.stdin.on('error', reject);
    });
}

async function main() {
    const opts = parseArgs(process.argv);

    if (!opts.input && !opts.stdin) {
        console.error('Usage: node report.js <input.json> [--redact=true|false] [--output=<file>]');
        console.error('       mcptrust check ... | node report.js --stdin [--redact=true|false]');
        process.exit(1);
    }

    let data;
    try {
        let content;
        if (opts.stdin) {
            content = await readStdin();
        } else {
            content = fs.readFileSync(opts.input, 'utf8');
        }
        data = JSON.parse(content);
    } catch (err) {
        console.error(`Error reading input: ${err.message}`);
        process.exit(1);
    }

    const report = generateReport(data, opts.redact);

    if (opts.output) {
        fs.writeFileSync(opts.output, report);
    } else {
        console.log(report);
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { generateReport, truncateHash, scrubSecrets, redactUri, groupBySeverity };
}

if (require.main === module) {
    main();
}
