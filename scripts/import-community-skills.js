#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const args = parseArgs(process.argv.slice(2));
const repoRoot = path.resolve(__dirname, '..');
const sourceRoot = path.resolve(repoRoot, args.source || '.vendor/anthropic-cybersecurity-skills-src');
const sourceSkillsDir = path.join(sourceRoot, 'skills');
const outputRoot = path.join(repoRoot, 'skills', 'community');
const noticePath = path.join(outputRoot, 'NOTICE.md');
const sourceRepo = 'mukul975/Anthropic-Cybersecurity-Skills';
const sourceUrl = 'https://github.com/mukul975/Anthropic-Cybersecurity-Skills';
const licenseUrl = `${sourceUrl}/blob/${args.commit || 'HEAD'}/LICENSE`;
const importedAt = args['imported-at'];
const commit = args.commit;

if (!commit) {
  fail('Missing required --commit <sha> argument.');
}

if (!importedAt) {
  fail('Missing required --imported-at <timestamp> argument.');
}

if (!fs.existsSync(sourceSkillsDir)) {
  fail(`Source skills directory not found: ${sourceSkillsDir}`);
}

const PRODUCT_PATTERNS = [
  [/^azure$/, 'Azure'],
  [/^(azure-sentinel|microsoft-sentinel|sentinel)$/, 'Microsoft Sentinel'],
  [/^(microsoft-defender|defender)$/, 'Microsoft Defender XDR'],
  [/^(defender-xdr|microsoft-defender-xdr)$/, 'Microsoft Defender XDR'],
  [/^(defender-for-cloud|microsoft-defender-for-cloud)$/, 'Microsoft Defender for Cloud'],
  [/^(defender-for-endpoint|microsoft-defender-for-endpoint|mde)$/, 'Microsoft Defender for Endpoint'],
  [/^(defender-for-identity|microsoft-defender-for-identity|mdi)$/, 'Microsoft Defender for Identity'],
  [/^(defender-for-office-365|microsoft-defender-for-office-365|mdo)$/, 'Microsoft Defender for Office 365'],
  [/^(entra|entra-id|microsoft-entra|azure-ad|azure-active-directory)$/, 'Microsoft Entra ID'],
  [/^(microsoft-365|m365|office-365|o365)$/, 'Microsoft 365'],
  [/^(graph-security|microsoft-graph-security|microsoft-graph)$/, 'Microsoft Graph Security API'],
  [/^(azure-monitor|log-analytics|azure-monitor-log-analytics)$/, 'Azure Monitor Log Analytics']
];

const CATEGORY_OVERRIDES = {
  'ai-security': 'AI Security',
  'api-security': 'API Security',
  'application-security': 'Application Security',
  'blockchain-security': 'Blockchain Security',
  'cloud-security': 'Cloud Security',
  'compliance-governance': 'Compliance & Governance',
  'container-security': 'Container Security',
  'cryptography': 'Cryptography',
  'data-protection': 'Data Protection',
  'deception-technology': 'Deception Technology',
  'devsecops': 'DevSecOps',
  'digital-forensics': 'Digital Forensics',
  'endpoint-security': 'Endpoint Security',
  'firmware-analysis': 'Firmware Analysis',
  'firmware-security': 'Firmware Security',
  'governance-risk-compliance': 'Governance, Risk & Compliance',
  'identity-access-management': 'Identity & Access Management',
  'identity-and-access-management': 'Identity & Access Management',
  'identity-security': 'Identity Security',
  'incident-response': 'Incident Response',
  'malware-analysis': 'Malware Analysis',
  'mobile-security': 'Mobile Security',
  'network-security': 'Network Security',
  'offensive-security': 'Offensive Security',
  'ot-ics-security': 'OT/ICS Security',
  'ot-security': 'OT Security',
  'penetration-testing': 'Penetration Testing',
  'phishing-defense': 'Phishing Defense',
  'privacy-compliance': 'Privacy & Compliance',
  'purple-team': 'Purple Team',
  'ransomware-defense': 'Ransomware Defense',
  'red-team': 'Red Team',
  'red-teaming': 'Red Teaming',
  'security-operations': 'Security Operations',
  'soc-operations': 'SOC Operations',
  'social-engineering-defense': 'Social Engineering Defense',
  'supply-chain-security': 'Supply Chain Security',
  'threat-detection': 'Threat Detection',
  'threat-hunting': 'Threat Hunting',
  'threat-intelligence': 'Threat Intelligence',
  'vulnerability-management': 'Vulnerability Management',
  'web-application-security': 'Web Application Security',
  'wireless-security': 'Wireless Security',
  'zero-trust': 'Zero Trust',
  'zero-trust-architecture': 'Zero Trust Architecture',
  cybersecurity: 'Cybersecurity'
};

const preservedFields = [
  'nist_csf',
  'nist_800_53',
  'cis_controls',
  'atlas_techniques',
  'd3fend_techniques',
  'nist_ai_rmf'
];

resetOutput(outputRoot);

const sourceSkillDirs = fs.readdirSync(sourceSkillsDir, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();

const authors = new Set();
const imported = [];

for (const skillDirName of sourceSkillDirs) {
  const sourceSkillPath = path.join(sourceSkillsDir, skillDirName, 'SKILL.md');
  if (!fs.existsSync(sourceSkillPath)) {
    continue;
  }

  const raw = fs.readFileSync(sourceSkillPath, 'utf8');
  const { data, body } = parseFrontmatter(raw, sourceSkillPath);
  const sourceSkill = slugify(data.name || skillDirName);
  const subdomain = slugify(data.subdomain || data.domain || 'uncategorized');
  const outputDir = path.join(outputRoot, subdomain);
  const outputPath = path.join(outputDir, `${sourceSkill}.md`);

  ensureDir(outputDir);

  const frontmatter = {
    title: titleFromSlug(sourceSkill),
    category: mapCategory(subdomain),
    difficulty: 'intermediate',
    mitre_attack: normalizeStringArray(firstDefined(data.mitre_attack, data.attack_techniques, data.attack_technique, data.attack)),
    products: extractProducts(data.tags),
    author: data.author || 'unknown',
    source_repo: sourceRepo,
    source_skill: sourceSkill,
    license: 'Apache-2.0',
    version: String(data.version || '1.0')
  };

  for (const field of preservedFields) {
    if (Object.prototype.hasOwnProperty.call(data, field)) {
      frontmatter[field] = normalizeFieldValue(data[field]);
    }
  }

  if (Array.isArray(data.tags)) {
    frontmatter.tags = normalizeStringArray(data.tags);
  } else if (typeof data.tags === 'string' && data.tags.trim()) {
    frontmatter.tags = [data.tags.trim()];
  } else {
    frontmatter.tags = [];
  }

  const doc = buildDocument(frontmatter, body);
  fs.writeFileSync(outputPath, doc, 'utf8');

  authors.add(String(frontmatter.author));
  imported.push({
    sourceSkill,
    subdomain,
    outputPath
  });
}

if (imported.length === 0) {
  fail('No skills were imported.');
}

fs.writeFileSync(noticePath, buildNotice({ commit, importedAt, authors, imported }), 'utf8');

console.log(`Imported ${imported.length} skills into ${outputRoot}`);
console.log(`NOTICE: ${noticePath}`);

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) {
      continue;
    }
    const key = token.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) {
      parsed[key] = true;
      continue;
    }
    parsed[key] = next;
    index += 1;
  }
  return parsed;
}

function parseFrontmatter(raw, filePath) {
  const normalized = raw.replace(/^\uFEFF/, '');
  const match = normalized.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
  if (!match) {
    fail(`Missing YAML frontmatter in ${filePath}`);
  }
  const data = yaml.load(match[1]) || {};
  const body = normalized.slice(match[0].length);
  return { data, body };
}

function buildDocument(frontmatter, body) {
  const yamlText = yaml.dump(frontmatter, {
    noRefs: true,
    lineWidth: 1000,
    sortKeys: false,
    quotingType: '\''
  }).trimEnd();
  return `---\n${yamlText}\n---\n${body}`;
}

function buildNotice({ commit, importedAt, authors, imported }) {
  const authorsList = Array.from(authors).sort((left, right) => left.localeCompare(right));
  const bySubdomain = imported.reduce((accumulator, item) => {
    accumulator[item.subdomain] = (accumulator[item.subdomain] || 0) + 1;
    return accumulator;
  }, {});
  const summaryLines = Object.keys(bySubdomain)
    .sort()
    .map((subdomain) => `- ${subdomain}: ${bySubdomain[subdomain]} skills`)
    .join('\n');
  const authorLines = authorsList.map((author) => `- ${author}`).join('\n');

  return [
    '# Community Skills Notice',
    '',
    'This directory contains community-contributed cybersecurity skills imported from the following Apache-2.0 licensed repository:',
    '',
    `- Source repository: ${sourceUrl}`,
    `- Pinned commit: ${commit}`,
    `- License: Apache-2.0 (${licenseUrl})`,
    `- Imported at: ${importedAt}`,
    `- Imported skill count: ${imported.length}`,
    '',
    'Imported subdomains:',
    summaryLines,
    '',
    'Original authors preserved in imported frontmatter:',
    authorLines,
    '',
    'The imported files are vendored copies transformed into the secops-squad community skill schema. Original author attribution is preserved per file in frontmatter.'
  ].join('\n');
}

function extractProducts(tags) {
  if (!Array.isArray(tags)) {
    return [];
  }
  const found = new Set();
  for (const tag of tags) {
    const normalizedTag = slugify(String(tag));
    for (const [pattern, product] of PRODUCT_PATTERNS) {
      if (pattern.test(normalizedTag)) {
        found.add(product);
      }
    }
  }
  return Array.from(found).sort((left, right) => left.localeCompare(right));
}

function mapCategory(subdomain) {
  return CATEGORY_OVERRIDES[subdomain] || titleFromSlug(subdomain);
}

function normalizeFieldValue(value) {
  if (Array.isArray(value)) {
    return normalizeStringArray(value);
  }
  if (typeof value === 'string') {
    return value.trim();
  }
  return value;
}

function normalizeStringArray(value) {
  if (!value) {
    return [];
  }
  const array = Array.isArray(value) ? value : [value];
  return array
    .map((item) => String(item).trim())
    .filter(Boolean);
}

function titleFromSlug(slug) {
  const acronyms = new Map([
    ['acl', 'ACL'],
    ['ad', 'AD'],
    ['ai', 'AI'],
    ['api', 'API'],
    ['apt', 'APT'],
    ['aws', 'AWS'],
    ['bola', 'BOLA'],
    ['cis', 'CIS'],
    ['ct', 'CT'],
    ['cve', 'CVE'],
    ['ddos', 'DDoS'],
    ['dns', 'DNS'],
    ['edr', 'EDR'],
    ['gcp', 'GCP'],
    ['gpo', 'GPO'],
    ['iam', 'IAM'],
    ['ics', 'ICS'],
    ['idor', 'IDOR'],
    ['iot', 'IoT'],
    ['ip', 'IP'],
    ['ips', 'IPS'],
    ['kql', 'KQL'],
    ['ldap', 'LDAP'],
    ['llm', 'LLM'],
    ['m365', 'M365'],
    ['mdr', 'MDR'],
    ['mitre', 'MITRE'],
    ['oci', 'OCI'],
    ['ot', 'OT'],
    ['rbac', 'RBAC'],
    ['s3', 'S3'],
    ['sas', 'SAS'],
    ['siem', 'SIEM'],
    ['soc', 'SOC'],
    ['sql', 'SQL'],
    ['ssh', 'SSH'],
    ['ssl', 'SSL'],
    ['tcp', 'TCP'],
    ['tls', 'TLS'],
    ['ttp', 'TTP'],
    ['udp', 'UDP'],
    ['url', 'URL'],
    ['usb', 'USB'],
    ['waf', 'WAF'],
    ['wifi', 'Wi-Fi'],
    ['windows', 'Windows'],
    ['wmi', 'WMI'],
    ['xdr', 'XDR'],
    ['xml', 'XML'],
    ['yaml', 'YAML']
  ]);

  return slug
    .split('-')
    .filter(Boolean)
    .map((part) => {
      const lower = part.toLowerCase();
      if (acronyms.has(lower)) {
        return acronyms.get(lower);
      }
      if (/^\d+$/.test(part)) {
        return part;
      }
      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join(' ');
}

function slugify(value) {
  return String(value)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'uncategorized';
}

function resetOutput(directory) {
  if (fs.existsSync(directory)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
  ensureDir(directory);
}

function ensureDir(directory) {
  fs.mkdirSync(directory, { recursive: true });
}

function firstDefined(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null) {
      return value;
    }
  }
  return undefined;
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
