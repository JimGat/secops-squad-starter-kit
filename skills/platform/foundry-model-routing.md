# Foundry Model Routing — Claude Fable 5 via Azure AI Foundry

> **Status:** Optional add-on skill — only active when `.secops/foundry.yaml` is present and `foundry.enabled: true`.
>
> **DEPRECATED_WHEN:** `claude-fable-5` is available in the GitHub Copilot model catalog. When that happens, remove `.secops/foundry.yaml`, delete this routing file, and use the native catalog model instead. No Azure Foundry resource is needed once Fable 5 is in the catalog.

---

## 1. Detection — Does This Installation Have Fable 5?

Before routing any task to Fable 5, check whether the add-on is deployed:

```
1. Look for .secops/foundry.yaml in the project root.
2. Parse the YAML. Check foundry.enabled == true.
3. Confirm foundry.endpoint and at least one entry in foundry.model_deployments
   where model_id == "claude-fable-5".
4. If any check fails → fall back to standard model. Do NOT error out.
```

**Detection pseudo-code (Python):**
```python
import yaml, os

def fable5_available(project_root: str) -> dict | None:
    config_path = os.path.join(project_root, ".secops", "foundry.yaml")
    if not os.path.exists(config_path):
        return None
    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    foundry = cfg.get("foundry", {})
    if not foundry.get("enabled", False):
        return None
    deployments = foundry.get("model_deployments", [])
    fable = next((d for d in deployments if d.get("model_id") == "claude-fable-5"), None)
    if not fable:
        return None
    return {
        "endpoint": foundry["endpoint"],
        "deployment_name": fable["deployment_name"],
        "resource_name": foundry["resource_name"],
    }
```

---

## 2. When to Route to Fable 5

Route to Fable 5 **only** for tasks that genuinely benefit from its extended context and deep reasoning. Unnecessary routing increases cost.

### ✅ Route to Fable 5

| Task | Why Fable 5 |
|------|-------------|
| **Deep SARIF analysis** — reviewing SARIF files with hundreds of findings, correlating across tools | Requires holding large result sets and cross-referencing rule metadata |
| **Large codebase security review** — reviewing entire repos or multi-file change sets for vulnerabilities | Context window advantage; standard models truncate or miss inter-file dependencies |
| **Multi-file vulnerability correlation** — tracing a vuln from source to sink across many files | Requires following data flows across file boundaries simultaneously |
| **Threat model generation** — full STRIDE/MITRE mapping on complex architectures with many components | Benefits from holistic reasoning over a large system description |
| **IR timeline reconstruction** — assembling an incident timeline from many log snippets | Long context lets it hold the full chronology at once |
| **Detection rule review** — reviewing 10+ KQL rules for logic overlap, gaps, and MITRE coverage | Holds the full rule set in context to find cross-rule patterns |

### ❌ Use Standard Model Instead

- Single-file queries or small code snippets
- Conversational Q&A, quick lookups, simple summaries
- Tasks where the context fits comfortably in a standard model
- Any task where cost sensitivity outweighs analytical depth

---

## 3. Calling the Endpoint

### Authentication

Fable 5 via Foundry supports **two auth modes** — use whichever fits your deployment:

**Mode A: Azure Entra ID (recommended for automated/agent use)**
```python
import subprocess, json

def get_entra_token() -> str:
    result = subprocess.run(
        ["az", "account", "get-access-token",
         "--resource", "https://cognitiveservices.azure.com",
         "--query", "accessToken", "-o", "tsv"],
        capture_output=True, text=True, check=True
    )
    return result.stdout.strip()
```

**Mode B: API Key**
```python
# Retrieve from Azure Key Vault or environment variable
import os
api_key = os.environ.get("FOUNDRY_API_KEY")
```

### SDK Pattern (Anthropic Python SDK)

```python
import anthropic, os

def get_fable5_client(endpoint: str, deployment_name: str) -> anthropic.Anthropic:
    """
    Returns an Anthropic client pointed at the Azure AI Foundry endpoint.
    Uses Entra token auth by default; falls back to API key if FOUNDRY_API_KEY is set.
    """
    token = get_entra_token()
    return anthropic.Anthropic(
        base_url=endpoint,
        default_headers={
            "Authorization": f"Bearer {token}",
            "x-ms-model-mesh-model-name": deployment_name,
        },
    )

# Usage
foundry = fable5_available(".")
if foundry:
    client = get_fable5_client(foundry["endpoint"], foundry["deployment_name"])
    response = client.messages.create(
        model=foundry["deployment_name"],
        max_tokens=4096,
        messages=[{"role": "user", "content": sarif_content}],
    )
```

### SDK Pattern (TypeScript / Node.js)

```typescript
import Anthropic from "@anthropic-ai/sdk";
import { execSync } from "child_process";

function getEntraToken(): string {
  return execSync(
    "az account get-access-token --resource https://cognitiveservices.azure.com --query accessToken -o tsv",
    { encoding: "utf-8" }
  ).trim();
}

function getFable5Client(endpoint: string, deploymentName: string): Anthropic {
  const token = getEntraToken();
  return new Anthropic({
    baseURL: endpoint,
    defaultHeaders: {
      Authorization: `Bearer ${token}`,
      "x-ms-model-mesh-model-name": deploymentName,
    },
  });
}
```

### Raw curl (for testing)

```bash
TOKEN=$(az account get-access-token \
  --resource https://cognitiveservices.azure.com \
  --query accessToken -o tsv)

ENDPOINT="https://secops-foundry.services.ai.azure.com/anthropic/v1"

curl -s -X POST "${ENDPOINT}/messages" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "fable5-secops",
    "max_tokens": 256,
    "messages": [{"role": "user", "content": "Summarize this SARIF finding in one sentence."}]
  }'
```

---

## 4. Pricing & Cost Controls

| Token type | Cost |
|-----------|------|
| Input | $10.00 / 1M tokens |
| Output | $50.00 / 1M tokens |
| Prompt cache hit | 90% discount on input |

**Cost guidance for agents:**
- Always use prompt caching for repeated system prompts or large context documents.
- For iterative SARIF review, cache the SARIF content as a user-turn prefix and vary only the analysis instruction.
- If the task can be broken into smaller chunks that fit a standard model, prefer that approach.
- Log token usage per call when running bulk analysis pipelines.

---

## 5. Safety Policy

Anthropic requires **30-day data retention** for Fable 5 on Azure AI Foundry. This is enforced at the Azure resource level and applies to all calls through this endpoint. Do not route PII or regulated data through Foundry unless your compliance review has cleared it for 30-day cloud retention.

---

## 6. Deprecation Path

This add-on exists because `claude-fable-5` is not yet in the GitHub Copilot model catalog. Once it is:

1. Remove `.secops/foundry.yaml` (or set `foundry.enabled: false`).
2. Delete `skills/platform/foundry-model-routing.md` (this file).
3. Delete `scripts/deploy-foundry-fable5.ps1` and `scripts/deploy-foundry-fable5.sh`.
4. Update agent prompts to reference the catalog model directly.
5. Optionally deprovision the Azure AI Foundry resource to stop billing.

The Azure resource can be deleted with:
```bash
az cognitiveservices account delete \
  --name secops-foundry \
  --resource-group rg-secops-ai
```

---

## 7. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `401 Unauthorized` | Re-run `az login`; Entra tokens expire after ~1 hour |
| `404 Not Found` on deployment | Verify `deployment_name` in `.secops/foundry.yaml` matches the Azure deployment |
| `429 Too Many Requests` | Foundry deployment capacity is low (default: 1K TPM); increase via `az cognitiveservices account deployment update` |
| Foundry config not found | Run `scripts/deploy-foundry-fable5.ps1` or `.sh` to create the deployment and config file |
| High cost | Enable prompt caching; audit which tasks are being routed to Fable 5 |
