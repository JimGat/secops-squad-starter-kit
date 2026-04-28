// MITRE ATT&CK Coverage Mapping — scans skill files and builds coverage analysis.
// No external dependencies. Pure Node.js.

'use strict';

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// MITRE ATT&CK Enterprise Matrix reference data (v15, April 2024)
// ---------------------------------------------------------------------------

const TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', techniqueCount: 18 },
  { id: 'TA0042', name: 'Resource Development', techniqueCount: 8 },
  { id: 'TA0001', name: 'Initial Access', techniqueCount: 10 },
  { id: 'TA0002', name: 'Execution', techniqueCount: 14 },
  { id: 'TA0003', name: 'Persistence', techniqueCount: 20 },
  { id: 'TA0004', name: 'Privilege Escalation', techniqueCount: 14 },
  { id: 'TA0005', name: 'Defense Evasion', techniqueCount: 43 },
  { id: 'TA0006', name: 'Credential Access', techniqueCount: 17 },
  { id: 'TA0007', name: 'Discovery', techniqueCount: 32 },
  { id: 'TA0008', name: 'Lateral Movement', techniqueCount: 9 },
  { id: 'TA0009', name: 'Collection', techniqueCount: 17 },
  { id: 'TA0011', name: 'Command and Control', techniqueCount: 16 },
  { id: 'TA0010', name: 'Exfiltration', techniqueCount: 9 },
  { id: 'TA0040', name: 'Impact', techniqueCount: 14 },
];

// Maps parent technique IDs to their primary tactics.
const TECHNIQUE_TACTIC_MAP = {
  T1595: ['TA0043'], T1592: ['TA0043'], T1589: ['TA0043'], T1590: ['TA0043'],
  T1591: ['TA0043'], T1598: ['TA0043'], T1597: ['TA0043'], T1596: ['TA0043'],
  T1593: ['TA0043'], T1594: ['TA0043'],
  T1583: ['TA0042'], T1586: ['TA0042'], T1584: ['TA0042'], T1587: ['TA0042'],
  T1585: ['TA0042'], T1588: ['TA0042'], T1608: ['TA0042'], T1650: ['TA0042'],
  T1189: ['TA0001'], T1190: ['TA0001'], T1133: ['TA0001', 'TA0003'],
  T1200: ['TA0001'], T1566: ['TA0001'], T1091: ['TA0001', 'TA0008'],
  T1195: ['TA0001'], T1199: ['TA0001'], T1078: ['TA0001', 'TA0003', 'TA0004', 'TA0005'],
  T1659: ['TA0001', 'TA0002'],
  T1059: ['TA0002'], T1609: ['TA0002'], T1610: ['TA0002'],
  T1203: ['TA0002'], T1559: ['TA0002'], T1106: ['TA0002'],
  T1053: ['TA0002', 'TA0003', 'TA0004'], T1129: ['TA0002'],
  T1072: ['TA0002'], T1569: ['TA0002'], T1204: ['TA0002'],
  T1047: ['TA0002'],
  T1098: ['TA0003', 'TA0004'], T1197: ['TA0003', 'TA0005'],
  T1547: ['TA0003', 'TA0004'], T1037: ['TA0003', 'TA0004'],
  T1176: ['TA0003'], T1554: ['TA0003'], T1136: ['TA0003'],
  T1543: ['TA0003', 'TA0004'], T1546: ['TA0003', 'TA0004'],
  T1525: ['TA0003'], T1556: ['TA0003', 'TA0005', 'TA0006'],
  T1137: ['TA0003'], T1542: ['TA0003', 'TA0005'],
  T1505: ['TA0003'], T1205: ['TA0003', 'TA0005'],
  T1053: ['TA0002', 'TA0003', 'TA0004'],
  T1548: ['TA0004', 'TA0005'], T1134: ['TA0004', 'TA0005'],
  T1068: ['TA0004'], T1055: ['TA0004', 'TA0005'],
  T1574: ['TA0003', 'TA0004'],
  T1006: ['TA0005'], T1014: ['TA0005'], T1027: ['TA0005'],
  T1036: ['TA0005'], T1070: ['TA0005'], T1202: ['TA0005'],
  T1218: ['TA0005'], T1220: ['TA0005'], T1222: ['TA0005'],
  T1480: ['TA0005'], T1550: ['TA0005', 'TA0008'],
  T1562: ['TA0005'], T1564: ['TA0005'], T1535: ['TA0005'],
  T1578: ['TA0005'], T1497: ['TA0005', 'TA0007'],
  T1110: ['TA0006'], T1003: ['TA0006'], T1558: ['TA0006'],
  T1539: ['TA0006'], T1111: ['TA0006'], T1187: ['TA0006'],
  T1056: ['TA0006', 'TA0009'], T1557: ['TA0006', 'TA0009'],
  T1528: ['TA0006'], T1649: ['TA0006'], T1552: ['TA0006'],
  T1212: ['TA0006'], T1621: ['TA0006'],
  T1087: ['TA0007'], T1010: ['TA0007'], T1217: ['TA0007'],
  T1580: ['TA0007'], T1538: ['TA0007'], T1526: ['TA0007'],
  T1069: ['TA0007'], T1057: ['TA0007'], T1012: ['TA0007'],
  T1018: ['TA0007'], T1518: ['TA0007'], T1082: ['TA0007'],
  T1016: ['TA0007'], T1049: ['TA0007'], T1033: ['TA0007'],
  T1007: ['TA0007'], T1124: ['TA0007'], T1613: ['TA0007'],
  T1614: ['TA0007'], T1622: ['TA0007'], T1615: ['TA0007'],
  T1654: ['TA0007'],
  T1021: ['TA0008'], T1080: ['TA0008'], T1534: ['TA0008'],
  T1570: ['TA0008'], T1563: ['TA0008'],
  T1557: ['TA0006', 'TA0009'], T1560: ['TA0009'], T1123: ['TA0009'],
  T1119: ['TA0009'], T1185: ['TA0009'], T1115: ['TA0009'],
  T1213: ['TA0009'], T1005: ['TA0009'], T1039: ['TA0009'],
  T1025: ['TA0009'], T1114: ['TA0009'], T1113: ['TA0009'],
  T1125: ['TA0009'], T1530: ['TA0009'],
  T1071: ['TA0011'], T1132: ['TA0011'], T1001: ['TA0011'],
  T1568: ['TA0011'], T1573: ['TA0011'], T1008: ['TA0011'],
  T1105: ['TA0011'], T1104: ['TA0011'], T1095: ['TA0011'],
  T1571: ['TA0011'], T1572: ['TA0011'], T1090: ['TA0011'],
  T1219: ['TA0011'], T1205: ['TA0003', 'TA0005', 'TA0011'],
  T1102: ['TA0011'],
  T1020: ['TA0010'], T1030: ['TA0010'], T1048: ['TA0010'],
  T1041: ['TA0010'], T1011: ['TA0010'], T1052: ['TA0010'],
  T1567: ['TA0010'], T1029: ['TA0010'], T1537: ['TA0010'],
  T1485: ['TA0040'], T1486: ['TA0040'], T1565: ['TA0040'],
  T1491: ['TA0040'], T1561: ['TA0040'], T1499: ['TA0040'],
  T1495: ['TA0040'], T1490: ['TA0040'], T1498: ['TA0040'],
  T1496: ['TA0040'], T1489: ['TA0040'], T1529: ['TA0040'],
  T1657: ['TA0040'],
};

// Canonical technique names
const TECHNIQUE_NAMES = {
  T1078: 'Valid Accounts', T1059: 'Command and Scripting Interpreter',
  T1071: 'Application Layer Protocol', T1110: 'Brute Force',
  T1566: 'Phishing', T1098: 'Account Manipulation',
  T1087: 'Account Discovery', T1021: 'Remote Services',
  T1048: 'Exfiltration Over Alternative Protocol',
  T1556: 'Modify Authentication Process',
  T1190: 'Exploit Public-Facing Application',
  T1530: 'Data from Cloud Storage', T1562: 'Impair Defenses',
  T1027: 'Obfuscated Files or Information', T1053: 'Scheduled Task/Job',
  T1090: 'Proxy', T1573: 'Encrypted Channel',
  T1105: 'Ingress Tool Transfer', T1136: 'Create Account',
  T1486: 'Data Encrypted for Impact',
  T1567: 'Exfiltration Over Web Service',
  T1539: 'Steal Web Session Cookie',
  T1133: 'External Remote Services', T1003: 'OS Credential Dumping',
  T1558: 'Steal or Forge Kerberos Tickets',
  T1203: 'Exploitation for Client Execution',
  T1547: 'Boot or Logon Autostart Execution',
  T1525: 'Implant Internal Image',
  T1537: 'Transfer Data to Cloud Account',
  T1114: 'Email Collection', T1550: 'Use Alternate Authentication Material',
  T1565: 'Data Manipulation', T1056: 'Input Capture',
  T1189: 'Drive-by Compromise', T1200: 'Hardware Additions',
  T1195: 'Supply Chain Compromise', T1199: 'Trusted Relationship',
  T1204: 'User Execution', T1047: 'Windows Management Instrumentation',
  T1134: 'Access Token Manipulation', T1068: 'Exploitation for Privilege Escalation',
  T1055: 'Process Injection', T1036: 'Masquerading', T1070: 'Indicator Removal',
  T1218: 'System Binary Proxy Execution', T1564: 'Hide Artifacts',
  T1003: 'OS Credential Dumping', T1552: 'Unsecured Credentials',
  T1528: 'Steal Application Access Token',
  T1018: 'Remote System Discovery', T1082: 'System Information Discovery',
  T1016: 'System Network Configuration Discovery',
  T1485: 'Data Destruction', T1491: 'Defacement',
  T1499: 'Endpoint Denial of Service', T1498: 'Network Denial of Service',
  T1496: 'Resource Hijacking', T1489: 'Service Stop',
  // Sub-techniques
  'T1078.004': 'Valid Accounts: Cloud Accounts',
  'T1110.003': 'Brute Force: Password Spraying',
  'T1566.001': 'Phishing: Spearphishing Attachment',
  'T1566.002': 'Phishing: Spearphishing Link',
  'T1059.001': 'Command and Scripting Interpreter: PowerShell',
  'T1003.006': 'OS Credential Dumping: DCSync',
  'T1558.001': 'Steal or Forge Kerberos Tickets: Golden Ticket',
  'T1558.003': 'Steal or Forge Kerberos Tickets: Kerberoasting',
  'T1550.002': 'Use Alternate Authentication Material: Pass the Hash',
  'T1087.001': 'Account Discovery: Local Account',
  'T1087.002': 'Account Discovery: Domain Account',
  'T1056.004': 'Input Capture: Credential API Hooking',
  'T1114.003': 'Email Collection: Email Forwarding Rule',
  'T1565.001': 'Data Manipulation: Stored Data Manipulation',
  'T1078.002': 'Valid Accounts: Domain Accounts',
};

// ---------------------------------------------------------------------------
// YAML frontmatter parser (minimal, zero-dep)
// ---------------------------------------------------------------------------

/**
 * Parse YAML frontmatter from markdown content.
 * Handles the subset needed for skill files: strings, arrays of strings.
 * @param {string} content - Raw markdown file content
 * @returns {{ frontmatter: Object, body: string }}
 */
function parseFrontmatter(content) {
  const fm = { frontmatter: {}, body: content };
  if (!content.startsWith('---')) return fm;

  const endIdx = content.indexOf('\n---', 3);
  if (endIdx === -1) return fm;

  const yamlBlock = content.substring(4, endIdx);
  fm.body = content.substring(endIdx + 4);

  const lines = yamlBlock.split('\n');
  let currentKey = null;
  let currentArray = null;

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (line.trim() === '' || line.trim().startsWith('#')) continue;

    // Array item under a key
    if (/^\s+-\s+/.test(line) && currentKey) {
      let val = line.replace(/^\s+-\s+/, '').trim();
      val = val.replace(/^["']|["']$/g, '').replace(/#.*$/, '').trim();
      if (!currentArray) currentArray = [];
      currentArray.push(val);
      fm.frontmatter[currentKey] = currentArray;
      continue;
    }

    // Key: value
    const match = line.match(/^([a-zA-Z_][a-zA-Z0-9_-]*)\s*:\s*(.*)/);
    if (match) {
      // Save previous array
      currentKey = match[1];
      const rawVal = match[2].trim();
      currentArray = null;

      if (rawVal === '' || rawVal === '[]') {
        fm.frontmatter[currentKey] = [];
        currentArray = fm.frontmatter[currentKey];
      } else if (rawVal.startsWith('[') && rawVal.endsWith(']')) {
        // Inline array
        fm.frontmatter[currentKey] = rawVal
          .slice(1, -1)
          .split(',')
          .map((s) => s.trim().replace(/^["']|["']$/g, ''))
          .filter(Boolean);
      } else {
        fm.frontmatter[currentKey] = rawVal.replace(/^["']|["']$/g, '');
      }
    }
  }

  return fm;
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

const TECHNIQUE_RE = /\bT1\d{3}(?:\.\d{3})?\b/g;

/**
 * Scan a skills directory and extract MITRE technique references from each skill.
 * @param {string} skillsDir - Path to the top-level skills/ directory
 * @returns {Object[]} Array of skill objects with MITRE data
 */
function scanSkills(skillsDir) {
  const resolved = path.resolve(skillsDir);
  if (!fs.existsSync(resolved)) return [];

  const skills = [];
  const categories = fs.readdirSync(resolved, { withFileTypes: true })
    .filter((d) => d.isDirectory() && !d.name.startsWith('.'));

  for (const cat of categories) {
    const catDir = path.join(resolved, cat.name);
    const files = fs.readdirSync(catDir).filter((f) => f.endsWith('.md'));

    for (const file of files) {
      const filePath = path.join(catDir, file);
      const content = fs.readFileSync(filePath, 'utf-8');
      const { frontmatter, body } = parseFrontmatter(content);

      const fmMitre = Array.isArray(frontmatter.mitre_attack)
        ? frontmatter.mitre_attack.filter((t) => /^T1\d{3}/.test(t))
        : [];

      const bodyMatches = [];
      let m;
      const re = new RegExp(TECHNIQUE_RE.source, 'g');
      while ((m = re.exec(body)) !== null) {
        if (!bodyMatches.includes(m[0])) bodyMatches.push(m[0]);
      }

      // Combined unique set
      const allTechniques = [...new Set([...fmMitre, ...bodyMatches])];

      skills.push({
        file,
        category: cat.name,
        title: frontmatter.title || file.replace('.md', ''),
        frontmatterMitre: fmMitre,
        bodyMitre: bodyMatches,
        allTechniques,
        path: filePath,
      });
    }
  }

  return skills;
}

/**
 * Build a structured coverage map from scanned skills.
 * @param {Object[]} skills - Output of scanSkills()
 * @returns {Object} Coverage map with techniques, tactics, products, etc.
 */
function buildCoverageMap(skills) {
  // technique → skills mapping
  const techniqueSkills = {};
  for (const skill of skills) {
    for (const tid of skill.allTechniques) {
      if (!techniqueSkills[tid]) techniqueSkills[tid] = [];
      techniqueSkills[tid].push({
        file: skill.file,
        category: skill.category,
        title: skill.title,
      });
    }
  }

  // Group by tactic
  const tacticCoverage = TACTICS.map((tactic) => {
    const covered = [];
    for (const [tid, skillList] of Object.entries(techniqueSkills)) {
      const parent = tid.includes('.') ? tid.split('.')[0] : tid;
      const tactics = TECHNIQUE_TACTIC_MAP[parent] || [];
      if (tactics.includes(tactic.id)) {
        covered.push({
          id: tid,
          name: TECHNIQUE_NAMES[tid] || TECHNIQUE_NAMES[parent] || tid,
          skills: skillList,
        });
      }
    }
    // Deduplicate by technique ID
    const seen = new Set();
    const unique = covered.filter((t) => {
      if (seen.has(t.id)) return false;
      seen.add(t.id);
      return true;
    });

    return {
      ...tactic,
      coveredTechniques: unique,
      coverageCount: unique.length,
      coveragePercent: Math.round((unique.length / tactic.techniqueCount) * 100),
    };
  });

  // Category breakdown
  const categoryMap = {};
  for (const skill of skills) {
    if (!categoryMap[skill.category]) {
      categoryMap[skill.category] = { skills: 0, techniques: new Set() };
    }
    categoryMap[skill.category].skills++;
    skill.allTechniques.forEach((t) => categoryMap[skill.category].techniques.add(t));
  }

  const totalUnique = new Set(Object.keys(techniqueSkills));
  const totalTechniques = TACTICS.reduce((sum, t) => sum + t.techniqueCount, 0);

  return {
    totalSkills: skills.length,
    totalUniqueTechniques: totalUnique.size,
    totalMitreTechniques: totalTechniques,
    overallCoverage: Math.round((totalUnique.size / totalTechniques) * 100),
    tacticCoverage,
    techniqueSkills,
    categoryMap,
  };
}

/**
 * Find coverage gaps — techniques not covered that are commonly used in attacks.
 * @param {Object} coverageMap - Output of buildCoverageMap()
 * @returns {Object} Gap analysis
 */
function findGaps(coverageMap) {
  // Top 20 most commonly observed techniques (MITRE Top Techniques for Enterprise)
  const topTechniques = [
    { id: 'T1059', name: 'Command and Scripting Interpreter' },
    { id: 'T1078', name: 'Valid Accounts' },
    { id: 'T1566', name: 'Phishing' },
    { id: 'T1027', name: 'Obfuscated Files or Information' },
    { id: 'T1053', name: 'Scheduled Task/Job' },
    { id: 'T1055', name: 'Process Injection' },
    { id: 'T1021', name: 'Remote Services' },
    { id: 'T1036', name: 'Masquerading' },
    { id: 'T1204', name: 'User Execution' },
    { id: 'T1218', name: 'System Binary Proxy Execution' },
    { id: 'T1070', name: 'Indicator Removal' },
    { id: 'T1047', name: 'Windows Management Instrumentation' },
    { id: 'T1134', name: 'Access Token Manipulation' },
    { id: 'T1003', name: 'OS Credential Dumping' },
    { id: 'T1068', name: 'Exploitation for Privilege Escalation' },
    { id: 'T1518', name: 'Software Discovery' },
    { id: 'T1082', name: 'System Information Discovery' },
    { id: 'T1016', name: 'System Network Configuration Discovery' },
    { id: 'T1033', name: 'System Owner/User Discovery' },
    { id: 'T1497', name: 'Virtualization/Sandbox Evasion' },
  ];

  const covered = new Set(Object.keys(coverageMap.techniqueSkills));
  const missing = topTechniques.filter((t) => !covered.has(t.id));
  const present = topTechniques.filter((t) => covered.has(t.id));

  // Identify weakest tactics
  const weakTactics = coverageMap.tacticCoverage
    .filter((t) => t.coveragePercent < 15)
    .sort((a, b) => a.coveragePercent - b.coveragePercent);

  return {
    topTechniquesCovered: present.length,
    topTechniquesTotal: topTechniques.length,
    missingTopTechniques: missing,
    coveredTopTechniques: present,
    weakTactics,
  };
}

/**
 * Generate a formatted report of the coverage map.
 * @param {Object} coverageMap - Output of buildCoverageMap()
 * @param {'json'|'markdown'|'summary'} format - Output format
 * @returns {string} Formatted report
 */
function generateReport(coverageMap, format = 'summary') {
  if (format === 'json') {
    return JSON.stringify(coverageMap, null, 2);
  }

  const gaps = findGaps(coverageMap);

  if (format === 'summary') {
    const lines = [
      `MITRE ATT&CK Coverage Summary`,
      `═══════════════════════════════`,
      `Skills scanned: ${coverageMap.totalSkills}`,
      `Unique techniques: ${coverageMap.totalUniqueTechniques}`,
      `Overall coverage: ${coverageMap.overallCoverage}%`,
      `Top-20 coverage: ${gaps.topTechniquesCovered}/${gaps.topTechniquesTotal}`,
      '',
      'Coverage by Tactic:',
    ];

    for (const tactic of coverageMap.tacticCoverage) {
      const bar = '█'.repeat(Math.round(tactic.coveragePercent / 5));
      lines.push(`  ${tactic.name.padEnd(24)} ${String(tactic.coverageCount).padStart(2)}/${String(tactic.techniqueCount).padStart(2)}  ${bar} ${tactic.coveragePercent}%`);
    }

    if (gaps.missingTopTechniques.length > 0) {
      lines.push('', 'Missing Top Techniques:');
      for (const t of gaps.missingTopTechniques) {
        lines.push(`  ⚠ ${t.id} — ${t.name}`);
      }
    }

    return lines.join('\n');
  }

  // format === 'markdown' handled externally (see docs/mitre-coverage.md)
  return JSON.stringify(coverageMap, null, 2);
}

module.exports = {
  scanSkills,
  buildCoverageMap,
  findGaps,
  generateReport,
  parseFrontmatter,
  TACTICS,
  TECHNIQUE_TACTIC_MAP,
  TECHNIQUE_NAMES,
};
