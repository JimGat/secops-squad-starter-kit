# Personas Guide

**What is a persona?** A pre-built team configuration that loads the right skills, templates, and workflows for your role in the SOC.

---

## What's a Persona?

A persona is a collection of:
- **Skills** — Knowledge packs (KQL hunts, SOAR playbooks, detection patterns)
- **Templates** — Ready-to-deploy queries and playbooks
- **Ceremonies** — Team rituals (threat model sessions, detection reviews)
- **Team Composition** — AI agent roles and routing
- **Routing Rules** — Which alerts/issues go to which agents for review

When you run `secops-squad init` and select a persona, the framework loads all of these automatically.

---

## All 6 Personas (Phase 2 Active)

### Phase 2: Live

#### 1. SOC Analyst ✅ LIVE (Phase 1)

**Status:** Available now | **Best for:** Alert triage, incident response, day-to-day SOC operations

**Team (4 agents):**
- **Bunk** (L1 Triage Analyst) — Alert triage, known-good/known-bad, playbook-driven response
- **Kima** (L2 Escalation Analyst) — Medium-severity investigation, entity enrichment, correlation
- **Freamon** (L3 Senior Analyst) — Advanced hunting, KQL engineering, cross-domain correlation
- **Daniels** (Shift Lead) — Incident assignment, workload balancing, stakeholder comms

**Key Skills:** All 6 Phase 1 skills + incident-investigation, teams-notification

**Loaded Skills:**
- Bunk: phishing-response, compromised-account
- Kima: sentinel-analytics-rules, sentinel-enrichment-ip, sentinel-enrichment-user
- Freamon: threat-hunting-foundations, cross-workspace-queries, ueba-patterns, defender-xdr-hunting
- Daniels: teams-notification, ticket-create

**Typical Workflow:**
1. Incident fires → Teams notification lands
2. Bunk performs L1 triage, runs phishing/compromised account playbooks
3. Kima enriches entities with IP/user context, decides escalation
4. Freamon runs advanced hunts if escalated, builds investigation chains
5. Daniels coordinates with stakeholders and shifts

**When to Use:**
- You're running a SOC with tiered analyst operations (L1/L2/L3)
- You need alert-driven incident response with clear escalation paths
- You want playbook-driven automation for common incident types

**Load this persona:**
```bash
secops-squad init
# Choose: SOC Analyst
```

**File:** [`personas/soc-analyst/`](../personas/soc-analyst/)

---

#### 2. Detection Engineering ✅ LIVE (Phase 2)

**Status:** Available now | **Best for:** Writing, tuning, and maintaining detection rules

**Team (4 agents):**
- **Daniels** (Detection Engineer) — Rule design, detection logic, MITRE mapping
- **Lester** (KQL Author) — Query authoring, performance optimization, correlations
- **Prop Joe** (Threat Modeler) — Technique mapping, coverage gaps, evasion assessment
- **Landsman** (QA Validator) — Rule validation, false positive testing, production sign-off

**Key Skills:** mitre-attack-mapping, detection-lifecycle, scheduled-rule-pattern, nrt-rule-pattern, threat-model-template, fusion-rule-context, watchlist-driven-detection, custom-kql-function

**Phase 3 Enhancement:** Access to [Threat Model Templates](../templates/threat-models/) for Initial Access, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Lateral Movement, Exfiltration, and Impact tactics.

**Typical Workflow:**
1. **Threat model session** with Prop Joe — Use MITRE threat model templates to define detection opportunities
2. **Lester** authors KQL detection query from threat model, Daniels reviews design
3. **Landsman** validates against threat model coverage, measures false positives
4. **Rule deployed** to Sentinel; gaps feed threat hunting backlog

**When to Use:**
- You're building or maintaining Sentinel analytics rules
- You want structured threat modeling before writing detection logic
- You need KQL code review and quality gates before production

**Load this persona:**
```bash
secops-squad init
# Choose: Detection Engineering
```

**File:** [`personas/detection-engineering/`](../personas/detection-engineering/)

---

## Phase 3: ADX Integration Across Personas

Azure Data Explorer enables long-term retention, time-series analytics, and federated querying. All personas can access ADX skills, but they're used differently:

### For Threat Hunting Persona
- Use ADX for **multi-month historical hunts** — Sentinel's 30-day retention isn't enough for APT campaign analysis
- Load ADX skills: `cluster-architecture`, `security-data-modeling`, `cross-cluster-queries`
- Example: Correlate suspicious login patterns across 6 months of archival data

### For Detection Engineering Persona
- Use ADX to **validate detection rules** against long-term patterns before deployment
- Combine threat model templates with ADX data to measure coverage effectiveness
- Example: Test a new C2 detection rule against 90 days of historical network traffic

### For Incident Response Persona
- Use ADX for **forensic analysis** — retrieve complete evidence timelines beyond Sentinel retention
- Load ADX skills: `migration-from-sentinel`, `long-term-retention-strategies`
- Example: Full forensic timeline of a compromised account's activities over 12 months

### For Full SOC Persona
- ADX is the **security data lake** — feeds hunting, detection validation, and forensic analysis
- All 8 ADX skills are loaded; use as needed for your workflow

**Quick Start:** See [ADX Setup Guide](../docs/adx-setup.md) for deployment and integration patterns.

---

## Phase 3: Threat Model Integration

The [10 Threat Model Templates](../templates/threat-models/) align with MITRE ATT&CK tactics. Use them in Detection Engineering and Incident Response:

### Detection Engineering Workflow
1. **Select a threat model** — e.g., [Credential Access template](../templates/threat-models/credential-access.md)
2. **Review MITRE techniques** — T1110 (brute force), T1555 (credentials from browsers), T1187 (credential phishing)
3. **Author KQL detection** for each technique
4. **Map KQL to detection rule** in Sentinel
5. **Document coverage** — what techniques are detected, what are gaps?

### Incident Response Workflow
1. **Incident occurs** — malware infection on 5 workstations
2. **Rapid threat model** — use [Impact template](../templates/threat-models/impact.md) to map attacker objectives
3. **Focused investigation** — correlate findings to specific MITRE techniques
4. **Evidence chain** — document which detection rules/hunts provided evidence

---

## How to Use Both ADX and Threat Models

A complete detection workflow using Phase 3 features:

```
1. Detection Engineer reviews Credential Access threat model
   ↓
2. Identifies T1110 (Brute Force) technique gap
   ↓
3. Authors KQL query for brute force detection
   ↓
4. Tests against ADX historical data (90-day lookback)
   ↓
5. Deploys rule to Sentinel with confidence
   ↓
6. If incident occurs, Incident Response team uses threat model
   to correlate findings and build forensic timeline in ADX
```

#### 3. Threat Hunting ✅ LIVE (Phase 2)

**Status:** Available now | **Best for:** Proactive, hypothesis-driven threat hunts across large data sets

**Team (4 agents):**
- **Omar** (Hunt Lead) — Hypothesis development, hunt planning, findings triage, recommendations
- **Slim Charles** (KQL Hunter) — Hunt query authoring, cross-domain correlation, anomaly detection
- **Bubbles** (OSINT Researcher) — Threat intelligence, adversary profiling, IOC collection, TTP tracking
- **Rhonda** (Reporting Analyst) — Hunt reports, evidence documentation, executive briefings

**Key Skills:** threat-hunting-foundations, cross-workspace-queries, ueba-patterns, defender-xdr-hunting, detection-tuning, entra-signin-analysis, cloud-security-posture, adx-integration, cluster-architecture, security-data-modeling

**Typical Workflow:**
1. Omar defines hunt hypothesis (e.g., "Look for persistence via scheduled tasks in critical systems")
2. Bubbles researches known adversary tactics, collects IOCs
3. Slim Charles authors hunt queries, finds suspicious events
4. Rhonda documents findings, recommends new detections to Engineering team

**When to Use:**
- You're building a proactive threat hunting program
- You need structured hypothesis-driven hunts with documented outcomes
- You want hunt findings to feed your detection engineering pipeline

**Load this persona:**
```bash
secops-squad init
# Choose: Threat Hunting
```

**File:** [`personas/threat-hunting/`](../personas/threat-hunting/)

---

#### 4. Cloud Security ✅ LIVE (Phase 2)

**Status:** Available now | **Best for:** Cloud posture, Defender for Cloud, identity and policy

**Team (3 agents):**
- **Avon** (Cloud Security Engineer) — Remediation, Defender for Cloud config, RBAC hardening
- **Stringer** (Policy Analyst) — Azure Policy, compliance frameworks, exemption management
- **D'Angelo** (Posture Reviewer) — CSPM assessments, Secure Score, trend analysis

**Key Skills:** cloud-security-posture, defender-for-cloud-policies, workspace-rbac, diagnostic-settings, entra-signin-analysis

**Typical Workflow:**
1. D'Angelo runs monthly CSPM assessment with Defender for Cloud
2. Identifies misconfigurations (unencrypted storage, open NSGs, weak RBAC)
3. Stringer creates/updates Azure Policy rules for enforcement
4. Avon remediates high-priority findings (applies patches, hardens RBAC)
5. Tracks remediation and Secure Score trends over time

**When to Use:**
- You're managing cloud security posture across Azure subscriptions
- You need structured policy management with compliance alignment
- You want regular posture assessments with tracked remediation

**Load this persona:**
```bash
secops-squad init
# Choose: Cloud Security
```

**File:** [`personas/cloud-security/`](../personas/cloud-security/)

---

#### 5. Incident Response ✅ LIVE (Phase 2)

**Status:** Available now | **Best for:** Formal IR procedures, forensic analysis, containment, recovery

**Team (4 agents):**
- **Rawls** (IR Lead) — Incident command, containment decisions, escalation, post-incident review
- **Sydnor** (Forensic Analyst) — Evidence collection, timeline reconstruction, impact assessment
- **Beadie** (Comms Coordinator) — Stakeholder updates, executive briefings, regulatory notification
- **Prez** (Threat Intel) — IOC research, adversary attribution, campaign analysis

**Key Skills:** incident-investigation, cross-workspace-queries, malware-containment, data-exfiltration-response, threat-intel-ingest, detection-tuning

**Typical Workflow:**
1. Major incident declared — Rawls convenes IR team
2. Sydnor begins evidence collection (memory dumps, disk images, logs)
3. Beadie notifies stakeholders, tracks regulatory/legal requirements
4. Prez researches adversary TTPs, collects related IOCs
5. Rawls coordinates containment decisions, tracks remediation
6. Post-incident: Lessons learned feed detection and process improvements

**When to Use:**
- You're building or formalizing an IR capability
- You need structured IR with clear command authority and role separation
- You want forensics, threat intel, and stakeholder comms coordinated during incidents

**Load this persona:**
```bash
secops-squad init
# Choose: Incident Response
```

**File:** [`personas/incident-response/`](../personas/incident-response/)

---

#### 6. Full SOC ✅ LIVE (Phase 2)

**Status:** Available now | **Best for:** Complete, mature SOC with all functions (triage, detection, hunting, automation, IR)

**Team (8 agents):**
- **Bunny Colvin** (SOC Manager) — Strategy, shift management, metrics, stakeholder relations
- **Bodie** (L1 Analyst) — Alert triage, playbook-driven response, queue hygiene
- **Poot** (L2 Analyst) — Medium-severity investigation, entity enrichment, escalation
- **Carver** (L3 Analyst) — Advanced investigation, cross-domain correlation, APT hunting
- **Ellis** (Detection Engineer) — Rule authoring, MITRE mapping, detection lifecycle
- **Snoop** (Hunt Lead) — Hypothesis development, proactive threat hunting, findings triage
- **Prop Joe** (Threat Intel) — Intelligence gathering, adversary profiling, IOC collection
- **Lester** (SOAR Orchestrator) — Playbook automation, response workflows, orchestration

**Key Skills:** All 36 Phase 3 skills (10 KQL + 10 SOAR + 8 Detection + 8 ADX)

**Typical Workflow:**
1. Incident fires → Bodie performs L1 triage
2. If playbook-driven (phishing, compromised account) → Lester runs automation
3. If escalated to L2 → Poot enriches entities, correlates signals
4. If complex → Carver runs advanced hunt or Snoop's team investigates
5. Ellis ensures new detections close gaps; Prop Joe tracks adversary changes
6. Bunny Colvin coordinates daily standups, shift handoffs, metrics reviews

**When to Use:**
- You're building a mature SOC covering all functions
- You want a single team configuration for triage + detection + hunting + IR
- You need cross-functional coordination (hunt findings → rules → automation)

**Load this persona:**
```bash
secops-squad init
# Choose: Full SOC
```

**File:** [`personas/full-soc/`](../personas/full-soc/)

---

## How to Switch Personas

### Check Current Persona
```bash
secops-squad status
```

Output shows:
```
secops-squad Configuration
─────────────────────────────
Team Name:    my-security-team
Persona:      soc-analyst
```

### Switch Personas (Phase 2)
```bash
secops-squad persona
```

Interactive prompt:
```
? Select a new persona:
  ❯ SOC Analyst (Phase 1)
    Detection Engineering (Phase 2)
    Threat Hunting (Phase 2)
    Cloud Security (Phase 2)
    Incident Response (Phase 2)
    Full SOC (Phase 2)
    Custom Persona...
```

### Manual Persona Switch (Now)
Edit `secops-squad.config.json`:

```json
{
  "persona": "detection-engineering"
}
```

Then run:
```bash
secops-squad status  # Reload and verify
```

---

## Persona File Structure

Each persona lives in `personas/<name>/`:

```
personas/detection-engineering/
├── README.md                — Persona overview
├── team.md                  — Team composition and AI roles
├── routing.md               — Issue routing rules
├── ceremonies.md            — Team rituals
├── skills.json              — List of loaded skills
└── .gitkeep
```

### What's in Each File?

#### `team.md`
Lists the AI agents assigned to this persona and their responsibilities:

```markdown
# Detection Engineering Team

## Agents

- **Daniels** (Detection Engineer) — Rule design, detection logic
- **Lester** (KQL Author) — Query authoring, performance optimization
```

#### `routing.md`
Defines which issues/alerts go to which agent:

```markdown
# Routing Rules

- `detection-request` issues → Daniels + Lester
- `threat-model` issues → Prop Joe
- `kql-review` issues → Lester
- `qa-review` issues → Landsman
```

#### `ceremonies.md`
Team rituals and governance:

```markdown
# Ceremonies

## Threat Model Session
When: Before each new detection rule
Who: Prop Joe + Daniels
Duration: 30 min
```

#### `skills.json`
Loaded skills for this persona:

```json
{
  "loaded": [
    "mitre-attack-mapping",
    "detection-lifecycle",
    "scheduled-rule-pattern",
    "nrt-rule-pattern"
  ]
}
```

---

## Creating a Custom Persona

### Step 1: Create the Persona Directory

```bash
mkdir -p personas/my-custom-persona
```

### Step 2: Create Persona Files

Create `personas/my-custom-persona/team.md`:

```markdown
# My Custom Persona

A specialized team for [your use case].

## Team Composition

- **Freamon** (KQL Engineer)
- **Herc** (Automation)
```

Create `personas/my-custom-persona/routing.md`:

```markdown
# Routing Rules

- Custom issues → Team leads
```

Create `personas/my-custom-persona/ceremonies.md`:

```markdown
# Ceremonies

## Weekly Sync
- When: Monday 9am
- Duration: 1 hour
```

Create `personas/my-custom-persona/skills.json`:

```json
{
  "loaded": [
    "threat-hunting-foundations",
    "sentinel-analytics-rules",
    "phishing-response"
  ]
}
```

### Step 3: Point to Your Persona

Edit `secops-squad.config.json`:

```json
{
  "persona": "my-custom-persona"
}
```

### Step 4: Verify

```bash
secops-squad status
```

Should show:
```
Persona:      my-custom-persona
```

---

## Persona Governance

### Adding a New Skill to Your Persona

Edit `personas/<name>/skills.json`:

```json
{
  "loaded": [
    "threat-hunting-foundations",
    "sentinel-analytics-rules",
    "my-new-custom-skill"
  ]
}
```

### Modifying Team Composition

Edit `personas/<name>/team.md` to add/remove agents and change responsibilities.

### Updating Routing Rules

Edit `personas/<name>/routing.md` to change how issues flow to team members.

### Adding Ceremonies

Edit `personas/<name>/ceremonies.md` to define rituals, decision gates, and review processes.

---

## Persona vs Custom Skill

| | Persona | Skill |
|---|---------|-------|
| **What is it?** | Full team config (agents, routing, ceremonies, skills) | Individual knowledge pack (KQL hunt, SOAR playbook, detection pattern) |
| **When to use** | Define a complete SOC role/workflow | Add a single pattern or playbook |
| **Loaded how?** | `secops-squad init` or manual switch | Auto-included via persona, or `secops-squad skill <name>` |
| **Where does it live?** | `personas/<name>/` | `skills/<category>/<name>.md` |
| **Who creates it?** | Org/team admins | Any contributor |

---

## Contributing a Persona

Have a persona that works well for your team? Contribute it:

1. Create the full persona directory structure (team.md, routing.md, ceremonies.md, skills.json)
2. Test it locally with `secops-squad status`
3. Open a PR to `personas/` with the label `persona-request`
4. The squad reviews and merges

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full flow.

---

## Phase 1 vs Phase 2 vs Phase 3

| Capability | Phase 1 | Phase 2 | Phase 3 |
|-----------|---------|---------|---------|
| **Personas available** | SOC Analyst only | All 6 (+ custom) | All 6 + specialized |
| **Persona switching** | Manual (edit config) | Via CLI | Full automation |
| **Custom personas** | Yes (create by hand) | Yes (create by hand) | Via CLI scaffold |
| **Ceremony support** | Documented in team.md | Documented in team.md | Automated + tracked |
| **Dynamic skill loading** | Manual (edit config) | Manual (edit config) | Via CLI |

---

## FAQ

**Q: Can I have multiple personas loaded at once?**

A: Not yet. Phase 2 is single-persona. Phase 3 will support multi-persona teams with cross-functional skill loading.

**Q: I want Detection Engineering + Threat Hunting skills in SOC Analyst.**

A: For now, edit `personas/soc-analyst/skills.json` and add the skills manually. In Phase 3, use `secops-squad skill <name>` to add ad-hoc skills.

**Q: Can I modify a built-in persona?**

A: Yes! Create a copy: `cp -r personas/soc-analyst personas/my-soc-variant`, then edit it and set `persona: my-soc-variant` in your config.

**Q: What's the difference between a persona and a team?**

A: A **persona** is the *configuration* (skills, routing, ceremonies). A **team** is the *execution* (specific people/agents assigned). One persona can run multiple teams.

**Q: Can I use personas from other repositories?**

A: Not yet. Phase 3 will support remote persona templates. For now, copy and customize locally.

---

**Ready to switch personas?** Run `secops-squad init` and pick your team.

**Last Updated:** 2026-04-28  
**Phase 2:** All 6 personas live and ready to use

## How to Switch Personas

### Check Current Persona
```bash
secops-squad status
```

Output shows:
```
secops-squad Configuration
─────────────────────────────
Team Name:    my-security-team
Persona:      soc-analyst
```

### Switch Personas (Phase 2)
In Phase 2, this command will work:

```bash
secops-squad persona
```

Interactive prompt:
```
? Select a new persona:
  ❯ SOC Analyst
    Detection Engineer     (Phase 2)
    Threat Hunter          (Phase 2)
    Cloud Security         (Phase 2)
    Incident Response      (Phase 2)
    Full SOC               (Phase 2)
    Custom Persona...      (Create your own)
```

### Manual Persona Switch (Now)
Edit `secops-squad.config.json`:

```json
{
  "persona": "soc-analyst"
}
```

Then run:
```bash
secops-squad status  # Reload and verify
```

---

## Persona File Structure

Each persona lives in `personas/<name>/`:

```
personas/soc-analyst/
├── README.md                — Persona overview
├── team.md                  — Team composition and AI roles
├── routing.md               — Issue routing rules
├── ceremonies.md            — Team rituals (threat model, detection review)
├── skills.json              — List of loaded skills
└── .gitkeep
```

### What's in Each File?

#### `team.md`
Lists the AI agents assigned to this persona and their responsibilities:

```markdown
# SOC Analyst Team

## Agents

- **Kima** (SecOps Engineer) — Routes alerts, prioritizes incidents
- **Freamon** (KQL Engineer) — Runs hunts, investigates incidents
- **Herc** (Automation) — Deploys playbooks, orchestrates responses
- **Carver** (QA) — Validates queries, reviews detections
```

#### `routing.md`
Defines which issues/alerts go to which agent:

```markdown
# Routing Rules

- `hunt-request` issues → Freamon (KQL Engineer)
- `playbook-request` issues → Herc (Automation)
- `detection-request` issues → Kima (SecOps Engineer), reviewed by Carver
- Sentinel incidents (phishing) → Auto-route to Herc's playbook
- Sentinel incidents (identity) → Auto-route to Kima's investigation
```

#### `ceremonies.md`
Team rituals and governance:

```markdown
# Ceremonies

## Threat Model Session
When: Every new detection rule
Who: Kima (SecOps Engineer), McNulty (Lead)
Why: Ensure detection aligns with threats, MITRE ATT&CK, and SOC mission
Duration: 30 min
```

#### `skills.json`
Loaded skills for this persona:

```json
{
  "loaded": [
    "threat-hunting-foundations",
    "sentinel-analytics-rules",
    "incident-investigation",
    "phishing-response",
    "compromised-account",
    "teams-notification"
  ],
  "templates": [
    "templates/kql/",
    "templates/bicep/"
  ]
}
```

---

## Creating a Custom Persona

### Step 1: Create the Persona Directory

```bash
mkdir -p personas/my-custom-persona
```

### Step 2: Create Persona Files

Create `personas/my-custom-persona/team.md`:

```markdown
# My Custom Persona

A specialized team for [your use case].

## Team Composition

- **Freamon** (KQL Engineer)
- **Herc** (Automation)
```

Create `personas/my-custom-persona/routing.md`:

```markdown
# Routing Rules

- Custom issues → Team leads
```

Create `personas/my-custom-persona/ceremonies.md`:

```markdown
# Ceremonies

## Weekly Sync
- When: Monday 9am
- Duration: 1 hour
- Attendees: Team
```

Create `personas/my-custom-persona/skills.json`:

```json
{
  "loaded": [
    "threat-hunting-foundations",
    "sentinel-analytics-rules",
    "phishing-response"
  ]
}
```

### Step 3: Point to Your Persona

Edit `secops-squad.config.json`:

```json
{
  "persona": "my-custom-persona"
}
```

### Step 4: Verify

```bash
secops-squad status
```

Should show:
```
Persona:      my-custom-persona
```

---

## Persona Governance

### Adding a New Skill to Your Persona

Edit `personas/<name>/skills.json`:

```json
{
  "loaded": [
    "threat-hunting-foundations",
    "sentinel-analytics-rules",
    "incident-investigation",
    "my-new-custom-skill"    ← Add here
  ]
}
```

### Modifying Team Composition

Edit `personas/<name>/team.md` to add/remove agents and change responsibilities.

### Updating Routing Rules

Edit `personas/<name>/routing.md` to change how issues flow to team members.

### Adding Ceremonies

Edit `personas/<name>/ceremonies.md` to define rituals, decision gates, and review processes.

---

## Persona vs Custom Skill

| | Persona | Skill |
|---|---------|-------|
| **What is it?** | Full team config (agents, routing, ceremonies, skills) | Individual knowledge pack (KQL hunt, SOAR playbook, detection pattern) |
| **When to use** | Define a complete SOC role/workflow | Add a single pattern or playbook |
| **Loaded how?** | `secops-squad init` or manual switch | Auto-included via persona, or `secops-squad skill <name>` |
| **Where does it live?** | `personas/<name>/` | `skills/<category>/<name>.md` |
| **Who creates it?** | Org/team admins | Any contributor |

---

## Contributing a Persona

Have a persona that works well for your team? Contribute it:

1. Create the full persona directory structure (team.md, routing.md, ceremonies.md, skills.json)
2. Test it locally with `secops-squad status`
3. Open a PR to `personas/` with the label `persona-request`
4. The squad reviews and merges

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full flow.

---

## Phase 1 vs Phase 2

| Capability | Phase 1 | Phase 2 |
|-----------|---------|---------|
| **Personas available** | SOC Analyst only | All 6 (+ custom) |
| **Persona switching** | Manual (edit config) | Via CLI (`secops-squad persona`) |
| **Custom personas** | Yes (create by hand) | Yes (CLI scaffold: `secops-squad persona new`) |
| **Ceremony support** | Documented in team.md | Automated reminders and tracking |
| **Dynamic skill loading** | Manual (edit config) | Via CLI |

---

## FAQ

**Q: Can I have multiple personas loaded at once?**

A: Not yet. Phase 1 is single-persona. Phase 2 will support multi-persona teams with cross-functional skill loading.

**Q: I want Detection Engineering + Threat Hunting skills in SOC Analyst.**

A: For now, edit `personas/soc-analyst/skills.json` and add the skills manually. In Phase 2, use `secops-squad skill <name>` to add ad-hoc skills.

**Q: Can I modify the SOC Analyst persona?**

A: Yes! Create a copy: `cp -r personas/soc-analyst personas/my-soc-variant`, then edit it and set `persona: my-soc-variant` in your config.

**Q: What's the difference between a persona and a team?**

A: A **persona** is the *configuration* (skills, routing, ceremonies). A **team** is the *execution* (specific people/agents assigned). One persona can run multiple teams.

---

**Ready to create a custom persona?** Copy soc-analyst, edit team.md, and let your squad loose.

**Last Updated:** 2026-04-28  
**Phase 1:** SOC Analyst live; others coming Phase 2
