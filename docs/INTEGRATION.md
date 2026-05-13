# SecOps Squad Starter Kit — Integration Guide

> **Version:** 1.0 | **Last Updated:** 2026-05-04 | **Audience:** SecOps engineers connecting the starter kit to real environments

This guide walks you through connecting the starter kit to your Microsoft Security stack. Start with the prerequisites, then follow steps 1–6 in order. Multi-tenant (MSSP/Lighthouse) and sovereign cloud configurations are covered at the end.

---

## Prerequisites

| Requirement | Details |
|------------|---------|
| **GitHub Copilot license** | [aka.ms/githubcopilot](https://aka.ms/githubcopilot) (free for Microsoft FTEs) |
| **Node.js 18+** | [nodejs.org](https://nodejs.org/) or `winget install OpenJS.NodeJS.LTS` |
| **Git** | [git-scm.com](https://git-scm.com/) or `winget install Git.Git` |
| **Azure CLI** | `winget install Microsoft.AzureCLI` — required for workspace connections |
| **Az PowerShell modules** | `Install-Module Az.OperationalInsights, Az.SecurityInsights, Az.Monitor` |

### Required Azure Permissions

| Resource | Minimum Role |
|----------|-------------|
| Log Analytics workspace | `Log Analytics Reader` (query), `Contributor` (deploy) |
| Microsoft Sentinel | `Microsoft Sentinel Reader` (query), `Contributor` (deploy rules) |
| Resource group (SOAR) | `Logic App Contributor` (deploy playbooks) |
| Microsoft Graph | `SecurityEvents.Read.All`, `ThreatIndicators.Read.All` |
| Azure Lighthouse (MSSP) | `Microsoft Sentinel Contributor` + `Log Analytics Reader` (delegated) |

---

## Step 1: Initialize `.secops/`

Run the init wizard to scaffold your environment configuration:

```bash
# From your project root
npx secops-squad init
```

The wizard will:
1. Prompt for your **persona** (SOC Analyst, Detection Engineering, etc.)
2. Ask for your **Azure tenant ID** and **primary region**
3. Create `.secops/environment.yaml` with your org details
4. Scaffold workspace templates in `.secops/workspaces/`
5. Initialize `discovery-log.yaml` (empty, agents will populate it)
6. Copy persona files to `.squad/`

**Manual alternative** — copy from the sample and edit:

```bash
cp -r samples/secops-contoso/.secops .secops
# Edit .secops/environment.yaml with your tenant, region, and org details
```

### Verify Initialization

```bash
npx secops-squad doctor
```

The doctor command checks:
- ✅ `.secops/environment.yaml` exists and is valid YAML
- ✅ At least one workspace is configured
- ✅ `data-source-map.yaml` has at least one entry
- ✅ Persona is loaded in `.squad/`

---

## Step 2: Configure Workspace Connections

Create a workspace file for each Log Analytics workspace your SOC uses.

### 2.1 Find Your Workspace Details

```powershell
# Login to Azure
az login

# List Log Analytics workspaces
az monitor log-analytics workspace list \
  --query "[].{name:name, id:customerId, rg:resourceGroup, region:location}" \
  -o table
```

### 2.2 Create Workspace File

Create `.secops/workspaces/<name>.yaml` (use the sample as a template):

```yaml
schema_version: "1.0"

name: "soc-sentinel-prod"
workspace_id: "<workspace-guid>"
resource_group: "rg-soc-prod"
subscription: "<subscription-guid>"
region: "eastus2"

sentinel_enabled: true
tier: "PerGB2018"                  # or CapacityReservation
commitment_tier_gb: null           # set if using capacity reservation

retention:
  default_days: 90
  interactive_days: 90
  archive_days: 730

custom_tables: []                  # add non-standard tier tables here

data_connectors:                   # list your active connectors
  - name: "Microsoft Defender for Endpoint"
    status: "connected"
    tables: ["DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents"]

naming_conventions:
  analytics_rules: "{severity}-{mitre_tactic}-{description}"
  watchlists: "wl-{purpose}-{source}"
  workbooks: "wb-{domain}-{description}"
```

### 2.3 Set Default Workspace

In `.secops/environment.yaml`, set the `default_workspace` field to your primary workspace filename (without `.yaml`):

```yaml
default_workspace: "soc-sentinel-prod"
```

---

## Step 3: Set Up Data Source Mappings

Edit `.secops/data-sources/data-source-map.yaml` to map your tables to their locations.

This is **the most important file** — agents consult it before every query.

```yaml
schema_version: "1.0"

sources:
  SecurityEvent:
    location: "sentinel"             # sentinel | adx | external
    workspace: "soc-sentinel-prod"
    tier: "Analytics"                # Analytics | Basic | Sentinel data lake | Archive
    daily_gb: 12
    ingestion_method: "ama-agent"
    notes: "Windows Security Events via Azure Monitor Agent"

  SigninLogs:
    location: "sentinel"
    workspace: "soc-sentinel-prod"
    tier: "Analytics"
    daily_gb: 3
    ingestion_method: "connector"

  # ADX tables (if applicable)
  NetFlowLogs:
    location: "adx"
    cluster: "soc-adx-prod"
    database: "SecurityLake"
    daily_gb: 100
    notes: "High-volume network flow data in ADX"

  # External sources (non-Azure)
  CrowdStrikeAlerts:
    location: "external"
    api_endpoint: "https://api.crowdstrike.com"
    notes: "Pull via REST API, not stored in Sentinel"
```

**Tip:** You don't need to map every table upfront. Agents will discover unmapped tables during operations and append findings to `discovery-log.yaml` for your review.

---

## Step 4: Configure Identity Providers

### 4.1 Tenant Topology

Edit `.secops/identity/tenants.yaml`:

```yaml
schema_version: "1.0"

tenants:
  - id: "<your-tenant-guid>"
    name: "Production"
    type: "primary"                   # primary | secondary | managed | lighthouse-delegated
    cloud: "azure-commercial"
```

### 4.2 RBAC Conventions

Edit `.secops/identity/rbac-conventions.yaml` to document your naming patterns:

```yaml
schema_version: "1.0"

role_assignments:
  sentinel_reader: "Microsoft Sentinel Reader"
  sentinel_contributor: "Microsoft Sentinel Contributor"
  sentinel_responder: "Microsoft Sentinel Responder"

naming_pattern: "{role}-{scope}-{team}"
```

### 4.3 Azure CLI Authentication

```powershell
# Interactive login
az login --tenant <your-tenant-id>

# Verify access to your workspace
az monitor log-analytics query \
  --workspace <workspace-guid> \
  --analytics-query "SecurityEvent | take 1" \
  --timespan P1D
```

---

## Step 5: Enable MCP Servers

MCP (Model Context Protocol) servers extend agent capabilities. Configure in `.copilot/mcp-config.json`:

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "npx",
      "args": ["-y", "sentinel-mcp-server"],
      "env": {
        "AZURE_TENANT_ID": "${AZURE_TENANT_ID}",
        "AZURE_SUBSCRIPTION_ID": "${AZURE_SUBSCRIPTION_ID}",
        "SENTINEL_WORKSPACE_ID": "${SENTINEL_WORKSPACE_ID}"
      }
    },
    "defender": {
      "command": "npx",
      "args": ["-y", "defender-mcp-server"],
      "env": {
        "AZURE_TENANT_ID": "${AZURE_TENANT_ID}"
      }
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@anthropic/github-mcp-server"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

Set environment variables in your shell or `.env` file:

```bash
export AZURE_TENANT_ID="<your-tenant-guid>"
export AZURE_SUBSCRIPTION_ID="<your-subscription-guid>"
export SENTINEL_WORKSPACE_ID="<your-workspace-guid>"
export GITHUB_TOKEN="<your-github-pat>"
```

See `skills/msft-security/sentinel-mcp-server.md` and `skills/msft-security/defender-mcp-server.md` for detailed configuration.

---

## Step 6: Validate Connectivity

### 6.1 Run the Doctor

```bash
npx secops-squad doctor
```

Expected output:

```
✅ .secops/environment.yaml — valid
✅ .secops/workspaces/soc-sentinel-prod.yaml — valid
✅ .secops/data-sources/data-source-map.yaml — 5 sources mapped
✅ Persona: soc-analyst — loaded
✅ Azure CLI — authenticated (tenant: Contoso Production)
✅ KQL validator — functional
```

### 6.2 Test a KQL Query

```bash
npx secops-squad kql validate
```

### 6.3 Test Graph Security API

```powershell
# Using the built-in library
node -e "
  const { createClient } = require('./lib/graph-security');
  const client = createClient();
  client.alerts.list({ top: 1 }).then(console.log);
"
```

---

## Multi-Tenant Setup (MSSP / Lighthouse)

For MSSPs managing multiple customer tenants:

### 1. Set Organization Type

In `.secops/environment.yaml`:

```yaml
organization:
  org_type: "mssp"
```

### 2. Configure Lighthouse Delegations

```yaml
lighthouse:
  delegations:
    - customer_tenant: "<customer-tenant-guid>"
      customer_name: "Customer A"
      delegated_roles:
        - "Microsoft Sentinel Contributor"
        - "Log Analytics Reader"
      delegated_scopes:
        - "/subscriptions/<sub-id>/resourceGroups/rg-soc"
      limitations:
        - "No Entra ID access in customer tenant"
        - "Playbooks require customer-side managed identity"
```

### 3. Add Managed Customers

```yaml
managed_customers:
  - name: "Customer A"
    tenant_id: "<customer-a-tenant-id>"
    access_type: "lighthouse"          # lighthouse | guest-account | csp | direct
    delegated_subscriptions:
      - id: "<sub-id>"
        delegated_rg: ["rg-soc-*"]
    sentinel_workspace: "cust-a-sentinel"
```

### 4. Create Per-Customer Workspaces

Create separate workspace files: `.secops/workspaces/cust-a-sentinel.yaml`, etc.

### 5. Load MSSP Orchestration Skill

Ensure `skills/orchestration/mssp-workflows.md` is in your persona's skill set.

See `skills/platform/multi-tenant-support.md` for complete MSSP patterns.

---

## Gov Cloud Setup (Sovereign Clouds)

For Azure Government, Azure China, or Azure Stack:

### 1. Set Cloud Environment

In `.secops/environment.yaml`:

```yaml
organization:
  cloud: "azure-government"    # azure-government | azure-china | azure-stack
  primary_region: "usgovvirginia"
```

### 2. Configure Azure CLI

```powershell
# Set cloud environment
az cloud set --name AzureUSGovernment

# Login to gov tenant
az login --tenant <gov-tenant-id>
```

### 3. Update API Endpoints

Gov cloud uses different API base URLs:

| Service | Commercial | Government |
|---------|-----------|------------|
| Graph API | `graph.microsoft.com` | `graph.microsoft.us` |
| ARM | `management.azure.com` | `management.usgovcloudapi.net` |
| Log Analytics | `api.loganalytics.io` | `api.loganalytics.us` |
| Sentinel | Standard ARM endpoints | Gov ARM endpoints |

Skills in `skills/platform/gov-cloud-support.md` cover endpoint configuration in detail.

### 4. Note Limitations

- Some data connectors are not available in gov clouds
- Copilot for Security availability may differ
- Check `skills/platform/gov-cloud-support.md` for the current feature matrix

---

## Troubleshooting

| Issue | Solution |
|-------|---------|
| `doctor` fails on workspace | Verify `workspace_id` GUID matches Azure Portal → Properties |
| `az login` expired | Run `az login --tenant <id>` again |
| KQL validation errors | Run `npm run validate:kql` locally; check syntax in skill files |
| MCP server won't start | Check `.copilot/mcp-config.json` syntax; verify env vars are set |
| No data in queries | Check data connector status in Sentinel portal → Data connectors |
| Lighthouse access denied | Verify delegated roles and scopes in Azure Portal → Service providers |
| Rate limiting errors | Check `skills/powershell/rate-limiting.md` for retry patterns |
| Gov cloud endpoints fail | Verify `az cloud set` matches `environment.yaml` cloud setting |
| Discovery log growing large | Archive old entries; promote confirmed facts to authoritative files |

---

## Related Documentation

- [Architecture Guide](ARCHITECTURE.md) — Full platform architecture
- [`.secops/` Schema Reference](SECOPS_SCHEMA.md) — Complete field-level docs
- [Getting Started](getting-started.md) — Installation and first hunt
- [ADX Setup Guide](adx-setup.md) — Azure Data Explorer configuration
- [Graph Security API](graph-security-api.md) — Library usage and auth flows
