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

## Available Personas

### Phase 1: Live

#### SOC Analyst ✅ LIVE
| Property | Value |
|----------|-------|
| **Status** | Available now |
| **Best for** | Alert triage, incident response, day-to-day SOC operations |
| **Loaded Skills** | All 6 Phase 1 skills (3 KQL, 3 SOAR) |
| **Loaded Templates** | KQL hunting queries, SOAR playbook scaffolds |
| **Team Size** | 1+ analysts (works solo or in a team) |
| **Time to Productive** | ~10 minutes |

**What you get:**
- **Threat Hunting Foundations** (KQL) — Proactive hypothesis-driven hunts
- **Sentinel Analytics Rules** (KQL) — Deploy automated detections
- **Incident Investigation** (KQL) — Reactive triage and forensics
- **Phishing Response** (SOAR) — Auto-remediate phishing incidents
- **Compromised Account Response** (SOAR) — Contain compromised identities
- **Teams Notification** (SOAR) — Rich incident alerts to Teams

**Typical workflow:**
1. Incident fires → Teams notification lands
2. Analyst opens incident, runs investigation queries
3. SOAR playbook auto-remediates (phishing removal, account lockdown)
4. Analyst approves containment or manually intervenes

**Load this persona:**
```bash
secops-squad init
# Choose: SOC Analyst
```

---

### Phase 2: Planned

#### Detection Engineering (Coming Phase 2)
**Best for:** Writing, tuning, and maintaining detection rules.

**Will include:**
- Advanced Sentinel Analytics Rules patterns
- KQL optimization for performance
- Detection rule tuning and false positive reduction
- MITRE ATT&CK mapping governance
- Analytics rule versioning and lifecycle management
- Threat model ceremony for new detections
- Carver's QA validation patterns

---

#### Threat Hunting (Coming Phase 2)
**Best for:** Proactive, hypothesis-driven threat hunts across large data sets.

**Will include:**
- Extended threat hunting methodology
- Hypothesis library (campaigns, persistence, lateral movement patterns)
- Azure Data Explorer (ADX) for long-term analytics
- Behavioral baselining at scale
- Hunt documentation and reporting
- Campaign tracking and retro-hunting

---

#### Cloud Security (Coming Phase 2)
**Best for:** Cloud posture management, Defender for Cloud, identity protection.

**Will include:**
- Defender for Cloud governance patterns
- Cloud identity and compliance queries
- CSPM rule tuning
- Entra ID risk investigation
- Azure resource configuration audit
- Compliance mapping (CIS, PCI, SOC2)

---

#### Incident Response (Coming Phase 2)
**Best for:** Formal IR procedures, forensic analysis, containment, recovery.

**Will include:**
- IR procedures and checklists
- Evidence collection workflows
- Forensic analysis patterns
- Containment playbooks
- Eradication and recovery checklists
- Post-incident reporting

---

#### Full SOC (Coming Phase 2)
**Best for:** Small teams that wear every hat.

**Will include:**
- All skills from all personas
- Cross-functional routing (alerts to right specialists)
- Unified reporting and metrics
- Shared ceremonies (all-hands threat models, SOC standups)

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
