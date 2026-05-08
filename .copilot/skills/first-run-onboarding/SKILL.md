---
name: "first-run-onboarding"
description: "Detects first-run state and guides new users through connecting Azure CLI, discovering Sentinel workspaces, initializing .secops/, and optionally connecting GitHub CLI — one step at a time."
domain: "onboarding, environment-setup"
confidence: "high"
license: MIT
---

# First-Run Onboarding

Proactively detect when a user is new or partially configured, then guide them through connecting their environment — one step at a time, no walls of text.

---

## When to Use This Skill

Use this skill **at session start** or when a user's request implies they haven't set up their environment:

- User says "help", "get started", "what do I do", "set up", or asks a question that requires Azure/Sentinel but nothing is configured
- Agent detects missing tools or configuration during normal operation
- User returns to a partially-configured environment

**Do NOT use** if the environment is already fully connected. A fully connected environment has:
- `az account show` succeeds
- `.secops/` directory exists with `environment.yaml`
- At least one workspace in `.secops/workspaces/`

---

## Step 0: Detect First-Run Signals

Run these checks silently at session start. Do not print raw command output — interpret the results.

### Check 1: Does `.secops/` exist?

```bash
test -d .secops && echo "EXISTS" || echo "MISSING"
```

- **MISSING** → User has never initialized. This is a first run.
- **EXISTS** → Check if it has real content (not just template defaults).

### Check 2: Is `.secops/environment.yaml` configured?

```bash
cat .secops/environment.yaml 2>/dev/null | head -5
```

- If organization name is `"Contoso Corp"` → template defaults, treat as unconfigured.
- If file is missing or empty → unconfigured.

### Check 3: Are any workspaces configured?

```bash
ls .secops/workspaces/*.yaml 2>/dev/null | wc -l
```

- **0** → No workspaces connected.

### Check 4: Is Azure CLI authenticated?

```bash
az account show --output json 2>/dev/null
```

- **Fails or empty** → Not logged in.
- **Succeeds** → Extract subscription name, ID, and tenant ID for later use.

### Check 5: Is GitHub CLI authenticated?

```bash
gh auth status 2>/dev/null
```

- **Fails** → Not authenticated.
- **Succeeds** → Logged in, note the account.

### Decision Matrix

| .secops/ | az login | workspaces | gh auth | State |
|----------|----------|------------|---------|-------|
| ❌ | ❌ | ❌ | ❌ | **Full first run** — start from Step 1 |
| ❌ | ✅ | ❌ | ❌ | **Azure connected, nothing else** — skip to Step 2 |
| ✅ | ✅ | ❌ | ❌ | **Initialized but no workspaces** — skip to Step 2 |
| ✅ | ✅ | ✅ | ❌ | **Core ready, gh optional** — offer Step 4 |
| ✅ | ✅ | ✅ | ✅ | **Fully connected** — no onboarding needed |
| ✅ | ❌ | any | any | **Re-auth needed** — start at Step 1 |

---

## Greeting: Welcome the User

When first-run signals are detected, greet warmly. Keep it to 2-3 sentences.

**Example greeting (full first run):**

> Welcome to secops-squad! This tool helps you hunt threats, build detections, and manage incidents across your Microsoft Security stack. Let's get your environment connected — it takes about 5 minutes.

**Example greeting (partial setup):**

> Welcome back! Looks like your Azure connection is set up but you haven't connected a Sentinel workspace yet. Want to pick up where we left off?

**Rules:**
- Do NOT list all prerequisites upfront
- Do NOT dump a numbered list of everything that needs to happen
- Offer to start the next uncompleted step
- Let the user say "I'll do this later" at any point — respect it

---

## Step 1: Connect Azure CLI

**Goal:** Get `az account show` returning a valid subscription.

### 1a. Check if Azure CLI is installed

```bash
az --version 2>/dev/null | head -1
```

- **Not found** → Tell the user:
  > Azure CLI isn't installed yet. You can install it from https://learn.microsoft.com/cli/azure/install-azure-cli — on Windows, `winget install Microsoft.AzureCLI` is the fastest way. Let me know when it's installed and I'll continue.

  Then **stop and wait**. Don't proceed until `az --version` succeeds.

- **Found** → Continue to 1b.

### 1b. Log in to Azure

```bash
az account show --output json 2>/dev/null
```

- **Already logged in** → Tell the user which subscription they're on and ask if it's the right one.
- **Not logged in** → Guide them:

  > Let's connect to Azure. I'll open a browser login for you.

  Then run:
  ```bash
  az login
  ```

  This opens a browser window. Wait for completion, then verify:
  ```bash
  az account show --query "{name:name, id:id, tenantId:tenantId}" --output table
  ```

### 1c. Select subscription (if needed)

If the user has multiple subscriptions, list them:

```bash
az account list --query "[?state=='Enabled'].{Name:name, Id:id, IsDefault:isDefault}" --output table
```

If the default subscription isn't where their security resources live:

```bash
az account set --subscription "<subscription-id>"
```

**Confirm:** "You're connected to **[subscription name]**. Is this the subscription where your Sentinel workspace lives?"

### Step 1 complete when:
- `az account show` returns a valid subscription
- User confirms it's the right subscription

---

## Step 2: Discover and Connect Sentinel Workspace

**Goal:** Find the user's Sentinel workspace and write it to `.secops/workspaces/`.

### 2a. List Log Analytics workspaces

```bash
az monitor log-analytics workspace list --query "[].{Name:name, ResourceGroup:resourceGroup, Location:location, Id:customerId}" --output table
```

- **No workspaces found** → The subscription may not have one, or they may need a different subscription.
  > I didn't find any Log Analytics workspaces in this subscription. Do you want to try a different subscription, or do you need to create a workspace first?

- **One workspace** → Confirm it's the right one.
- **Multiple workspaces** → Present a numbered list and let the user pick.

### 2b. Check for Sentinel on the workspace

For the selected workspace, check if Sentinel is enabled:

```bash
az rest --method GET --url "https://management.azure.com/subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.OperationsManagement/solutions/SecurityInsights({workspace-name})?api-version=2015-11-01-preview" 2>/dev/null
```

- **Succeeds** → Sentinel is enabled. Great.
- **Fails (404)** → Sentinel isn't enabled on this workspace.
  > This workspace doesn't have Microsoft Sentinel enabled. You can still use it for log analytics, but detection rules and incident management won't be available. Want to proceed anyway, or pick a different workspace?

### 2c. Connect the workspace

Use the CLI workspace connect command:

```bash
secops-squad workspace connect
```

This auto-discovers workspaces and writes `.secops/workspaces/<name>.yaml`. If the CLI isn't available or fails, guide manual creation:

```yaml
# .secops/workspaces/<workspace-name>.yaml
name: "<workspace-name>"
resource_group: "<resource-group>"
subscription_id: "<subscription-id>"
workspace_id: "<workspace-guid>"
region: "<location>"
sentinel_enabled: true
tier: "PerGB2018"
```

### Step 2 complete when:
- At least one file exists in `.secops/workspaces/`
- The workspace has been verified with `az monitor log-analytics workspace show`

---

## Step 3: Initialize .secops/ Configuration

**Goal:** Create the `.secops/` directory structure if it doesn't exist.

### 3a. Check if already initialized

```bash
test -f .secops/environment.yaml && echo "EXISTS" || echo "MISSING"
```

- **EXISTS** and not template defaults → Skip this step.
- **MISSING** or template defaults → Initialize.

### 3b. Run init

```bash
secops-squad init --secops
```

If the CLI init command isn't available, guide manual creation of the minimum structure:

```
.secops/
├── environment.yaml          # Organization, cloud type, tenant
├── workspaces/               # Workspace configs (from Step 2)
├── data-sources/
│   └── data-source-map.yaml  # Which tables are where
└── identity/
    └── tenants.yaml          # Tenant IDs
```

### 3c. Populate environment.yaml with discovered values

Using data from Steps 1-2, help the user fill in:

```yaml
organization:
  name: "<their org name>"
  cloud: azure-commercial   # or azure-government, azure-china
  primary_region: "<workspace region>"

tenants:
  - id: "<tenant-id from az account show>"
    type: primary
```

### Step 3 complete when:
- `.secops/environment.yaml` exists with real values (not template defaults)
- Organization name is set

---

## Step 4: GitHub CLI (Optional)

**Goal:** Connect GitHub CLI for PR workflows and issue tracking.

**Only offer this step after Steps 1-3 are complete.** Frame it as optional:

> Your Azure environment is all set! One more optional step: if you want to use secops-squad's PR workflows for deploying detection rules, we can connect GitHub. Want to set that up now, or skip it for later?

### 4a. Check if installed

```bash
gh --version 2>/dev/null
```

- **Not found** → "You can install GitHub CLI from https://cli.github.com or `winget install GitHub.cli` on Windows."

### 4b. Authenticate

```bash
gh auth status 2>/dev/null
```

- **Already authenticated** → Skip.
- **Not authenticated** →

  ```bash
  gh auth login
  ```

  This is interactive — let the user follow the prompts. Verify after:

  ```bash
  gh auth status
  ```

### Step 4 complete when:
- `gh auth status` shows an authenticated account, or user chose to skip

---

## Re-Entry: Picking Up Where They Left Off

When a user returns to a session with a partially-configured environment, do NOT restart from Step 1. Run the detection checks from Step 0 and jump to the first incomplete step.

**Examples:**

| Returning state | Agent behavior |
|----------------|----------------|
| az logged in, no workspace | "Your Azure connection is still active. Let's find your Sentinel workspace." → Jump to Step 2 |
| az token expired | "Your Azure session has expired. Let's refresh it." → Run `az login` only, then continue |
| workspace connected, no .secops/ | "I see your workspace but .secops/ isn't set up. Let me initialize that." → Jump to Step 3 |
| Everything connected | "You're all set! What would you like to work on?" → Skip onboarding entirely |

---

## After Onboarding: What's Next

Once the basic setup is complete, guide the user to their first task:

1. **If Sentinel is connected** → "Want to run a quick threat hunt to see what's in your environment?"
2. **If they mentioned a specific goal** → Route to that goal directly
3. **For exploration** → "You can ask me to hunt for threats, review your detection rules, or check your security posture. What sounds useful?"

**Do NOT** immediately jump into the full connectivity-setup skill. That's for power users who want to connect every Microsoft Security product. New users should start with one successful task.

### References for deeper setup

Once the user is comfortable, point them to:
- `skills/msft-security/connectivity-setup.md` — full product-by-product connectivity for Defender XDR, Defender for Cloud, MDI, MDE, and Entra ID Protection
- `.copilot/skills/secops-environment-context.md` — how agents read and use the `.secops/` configuration

---

## Anti-Patterns

These kill the onboarding experience. Don't do them.

| Anti-Pattern | Why It's Bad | Do This Instead |
|-------------|--------------|-----------------|
| Dump all prerequisites in a list | Overwhelming, user doesn't know where to start | Guide one step at a time |
| Repeat checks for things already working | Wastes time, feels broken | Skip what's already done |
| Require GitHub before Azure | GitHub is optional; Azure is the core dependency | Azure first, GitHub optional at the end |
| Show raw command output | Confusing for new users | Interpret results: "You're connected to subscription X" |
| Block on optional steps | User may not need GitHub today | Always offer "skip for now" |
| Reference `.secops/` before it exists | Confusing — the user hasn't created it yet | Create it first, reference it after |
| Run `secops-squad doctor` as first step | Doctor is a diagnostic tool, not a setup wizard | Use targeted checks, not a full diagnostic dump |
