---
title: "Sentinel Workbook Automation — Programmatic Dashboard Management"
category: soar
difficulty: advanced
products:
  - Microsoft Sentinel
  - Azure Monitor Workbooks
  - Azure Resource Manager
author: Herc
version: 1.0.0
last_updated: 2026-04-30
---

# Sentinel Workbook Automation — Programmatic Dashboard Management

## Overview

Azure Monitor Workbooks are the visualization backbone of every SOC — incident trends, compliance posture, hunting results, team performance. But deploying workbooks manually is a time sink: click through the portal, configure queries, set parameters, repeat across N workspaces. That doesn't scale.

This skill covers **programmatic workbook lifecycle management**: create, deploy, update, version-control, and migrate workbooks across workspaces entirely through automation. Every pattern here is scriptable — ARM/Bicep templates, REST API calls, PowerShell cmdlets, and CI/CD pipelines.

**What this skill covers:**
1. Workbook resource model and architecture
2. Programmatic creation with ARM/Bicep templates
3. Template engine patterns for parameterized workbooks
4. Full CRUD operations via REST API
5. CI/CD deployment and multi-workspace migration
6. Agent workflow patterns for SOC dashboard automation

## Environment Context

Before deploying workbooks, check `.secops/` for target workspace configuration:

```powershell
# Load workspace targets from .secops/
$workspaces = Get-ChildItem ".secops/workspaces/*.yaml" |
    ForEach-Object { Get-Content $_.FullName -Raw | ConvertFrom-Yaml }

$workspaces | ForEach-Object {
    Write-Host "Workspace: $($_.workspace.name) | Region: $($_.workspace.region) | ID: $($_.workspace.id)"
}
```

Check `.secops/compliance/requirements.yaml` for data residency constraints before deploying workbooks to specific regions.

---

## Workbook Architecture

### Resource Model

Azure Workbooks are ARM resources under `Microsoft.Insights/workbooks`:

```
/subscriptions/{subscriptionId}
  /resourceGroups/{resourceGroup}
    /providers/Microsoft.Insights/workbooks/{workbookId}
```

**Key properties:**

| Property | Description |
|----------|-------------|
| `displayName` | Human-readable workbook title |
| `category` | Gallery category (`workbook`, `sentinel`, `Azure Monitor`) |
| `sourceId` | Associated resource (Log Analytics workspace resource ID) |
| `serializedData` | JSON string containing all workbook content — queries, parameters, charts, grids |
| `kind` | `shared` (visible to others) or `user` (private) |
| `version` | Workbook schema version (typically `Notebook/1.0`) |

### Workbook vs. Workbook Template

| Aspect | Workbook | Workbook Template |
|--------|----------|-------------------|
| Resource type | `Microsoft.Insights/workbooks` | `Microsoft.Insights/workbooktemplates` |
| Scope | Specific workspace | Reusable across workspaces |
| Parameterized | Hardcoded resource IDs | Uses `{Subscription}`, `{Workspace}` tokens |
| Deployment | One instance per workspace | Template → instantiate per workspace |
| Gallery | Appears in "My workbooks" | Appears in gallery under category |
| Version control | By resource version | By template version + priority |

### Gallery Categories

Workbooks appear in the Sentinel gallery organized by category:

| Category | Purpose | Source |
|----------|---------|--------|
| `sentinel` | Sentinel-specific dashboards | Sentinel content hub |
| `workbook` | General workbooks | Azure Monitor |
| `Azure Sentinel` | Legacy Sentinel category | Backward compatibility |
| Custom | User-defined categories | Community / custom |

### Data Sources

Workbooks can query multiple data sources in a single dashboard:

| Source | Usage | Query Language |
|--------|-------|---------------|
| Log Analytics | Security logs, custom tables | KQL |
| Azure Resource Graph | Resource inventory, compliance | ARG KQL |
| Metrics | VM/Network/Storage performance | Metrics queries |
| Custom endpoints | External APIs, custom data | JSON REST |
| Merge | Combine multiple query results | Cross-source joins |

---

## Programmatic Creation

### ARM Template for Workbook Deployment

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "workbookDisplayName": {
      "type": "string",
      "defaultValue": "SOC Incident Overview",
      "metadata": { "description": "Display name for the workbook" }
    },
    "workspaceResourceId": {
      "type": "string",
      "metadata": { "description": "Full resource ID of the Log Analytics workspace" }
    },
    "workbookId": {
      "type": "string",
      "defaultValue": "[newGuid()]",
      "metadata": { "description": "Unique GUID for the workbook resource" }
    }
  },
  "resources": [
    {
      "type": "Microsoft.Insights/workbooks",
      "apiVersion": "2022-04-01",
      "name": "[parameters('workbookId')]",
      "location": "[resourceGroup().location]",
      "kind": "shared",
      "tags": {
        "hidden-title": "[parameters('workbookDisplayName')]",
        "deployed-by": "secops-squad-herc"
      },
      "properties": {
        "displayName": "[parameters('workbookDisplayName')]",
        "category": "sentinel",
        "sourceId": "[parameters('workspaceResourceId')]",
        "version": "Notebook/1.0",
        "serializedData": "[string(variables('workbookContent'))]"
      }
    }
  ],
  "variables": {
    "workbookContent": {
      "version": "Notebook/1.0",
      "items": [
        {
          "type": 1,
          "content": {
            "json": "# SOC Incident Overview\nDeployed by secops-squad automation."
          },
          "name": "header"
        },
        {
          "type": 9,
          "content": {
            "version": "KqlParameterItem/1.0",
            "parameters": [
              {
                "id": "time-range",
                "version": "KqlParameterItem/1.0",
                "name": "TimeRange",
                "type": 4,
                "typeSettings": {
                  "selectableValues": [
                    { "durationMs": 3600000 },
                    { "durationMs": 86400000 },
                    { "durationMs": 604800000 },
                    { "durationMs": 2592000000 }
                  ],
                  "allowCustom": true
                },
                "value": { "durationMs": 604800000 }
              }
            ]
          },
          "name": "parameters"
        },
        {
          "type": 3,
          "content": {
            "version": "KqlItem/1.0",
            "query": "SecurityIncident\n| where TimeGenerated {TimeRange}\n| summarize Count=count() by Severity\n| order by Count desc",
            "size": 1,
            "title": "Incidents by Severity",
            "queryType": 0,
            "resourceType": "microsoft.operationalinsights/workspaces",
            "visualization": "piechart"
          },
          "name": "severity-chart"
        }
      ]
    }
  }
}
```

### Bicep Template

```bicep
@description('Display name for the workbook')
param workbookDisplayName string = 'SOC Incident Overview'

@description('Full resource ID of the Log Analytics workspace')
param workspaceResourceId string

@description('Unique GUID for the workbook')
param workbookId string = newGuid()

@description('Location for the workbook resource')
param location string = resourceGroup().location

var workbookContent = {
  version: 'Notebook/1.0'
  items: [
    {
      type: 1
      content: { json: '# SOC Incident Overview\\nDeployed by secops-squad automation.' }
      name: 'header'
    }
    {
      type: 9
      content: {
        version: 'KqlParameterItem/1.0'
        parameters: [
          {
            id: 'time-range'
            version: 'KqlParameterItem/1.0'
            name: 'TimeRange'
            type: 4
            typeSettings: {
              selectableValues: [
                { durationMs: 3600000 }
                { durationMs: 86400000 }
                { durationMs: 604800000 }
                { durationMs: 2592000000 }
              ]
              allowCustom: true
            }
            value: { durationMs: 604800000 }
          }
        ]
      }
      name: 'parameters'
    }
    {
      type: 3
      content: {
        version: 'KqlItem/1.0'
        query: 'SecurityIncident\\n| where TimeGenerated {TimeRange}\\n| summarize Count=count() by Severity\\n| order by Count desc'
        size: 1
        title: 'Incidents by Severity'
        queryType: 0
        resourceType: 'microsoft.operationalinsights/workspaces'
        visualization: 'piechart'
      }
      name: 'severity-chart'
    }
  ]
}

resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: workbookId
  location: location
  kind: 'shared'
  tags: {
    'hidden-title': workbookDisplayName
    'deployed-by': 'secops-squad-herc'
  }
  properties: {
    displayName: workbookDisplayName
    category: 'sentinel'
    sourceId: workspaceResourceId
    version: 'Notebook/1.0'
    serializedData: string(workbookContent)
  }
}

output workbookResourceId string = workbook.id
```

### Workbook Item Types

| Type Code | Item Type | Description |
|-----------|-----------|-------------|
| 1 | Text (Markdown) | Static text, headers, instructions |
| 3 | Query (KQL) | KQL query with visualization (chart, grid, tile) |
| 9 | Parameters | Dynamic filters (time range, subscription, resource picker) |
| 10 | Text (HTML) | HTML content blocks |
| 11 | Links | Navigation links, tab groups |
| 12 | Group | Container for nested items |

### Building Workbook Items

**Query item with chart visualization:**

```json
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "SecurityIncident\n| where TimeGenerated > ago(30d)\n| summarize Count=count() by bin(TimeGenerated, 1d), Severity\n| render timechart",
    "size": 0,
    "title": "Daily Incident Trend",
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces",
    "visualization": "timechart",
    "chartSettings": {
      "seriesLabelSettings": [
        { "seriesName": "High", "color": "red" },
        { "seriesName": "Medium", "color": "orange" },
        { "seriesName": "Low", "color": "blue" }
      ]
    }
  },
  "name": "daily-trend"
}
```

**Grid item with column formatting:**

```json
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "SecurityIncident\n| where TimeGenerated > ago(7d)\n| where Status == 'New'\n| project Title, Severity, CreatedTime=TimeGenerated, Owner=OwnerEmail\n| sort by CreatedTime desc\n| take 50",
    "size": 0,
    "title": "Open Incidents",
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces",
    "visualization": "table",
    "gridSettings": {
      "formatters": [
        {
          "columnMatch": "Severity",
          "formatter": 18,
          "formatOptions": {
            "thresholdsOptions": "icons",
            "thresholdsGrid": [
              { "operator": "==", "thresholdValue": "High", "representation": "4", "text": "{0}" },
              { "operator": "==", "thresholdValue": "Medium", "representation": "2", "text": "{0}" },
              { "operator": "Default", "representation": "success", "text": "{0}" }
            ]
          }
        }
      ]
    }
  },
  "name": "open-incidents-grid"
}
```

**Dynamic parameter — workspace selector:**

```json
{
  "type": 9,
  "content": {
    "version": "KqlParameterItem/1.0",
    "parameters": [
      {
        "id": "workspace-selector",
        "version": "KqlParameterItem/1.0",
        "name": "Workspace",
        "type": 5,
        "isRequired": true,
        "multiSelect": false,
        "query": "resources\n| where type == 'microsoft.operationalinsights/workspaces'\n| project value=id, label=name, group=resourceGroup",
        "queryType": 1,
        "resourceType": "microsoft.resourcegraph/resources"
      },
      {
        "id": "time-range-param",
        "version": "KqlParameterItem/1.0",
        "name": "TimeRange",
        "type": 4,
        "isRequired": true,
        "typeSettings": {
          "selectableValues": [
            { "durationMs": 14400000, "createdTime": "2024-01-01T00:00:00Z", "isInitialTime": false, "grain": 1, "useDashboardTimeRange": false },
            { "durationMs": 86400000 },
            { "durationMs": 604800000 },
            { "durationMs": 2592000000 }
          ]
        },
        "value": { "durationMs": 604800000 }
      }
    ]
  },
  "name": "workbook-parameters"
}
```

---

## Template Engine Patterns

### Parameterized Workbook Templates

Create reusable templates that swap out workspace IDs, time ranges, and thresholds at deployment time:

```powershell
function New-WorkbookFromTemplate {
    param(
        [string]$TemplatePath,
        [string]$WorkspaceResourceId,
        [string]$ResourceGroup,
        [string]$WorkbookName,
        [hashtable]$Parameters = @{}
    )

    # Load template
    $template = Get-Content $TemplatePath -Raw

    # Replace standard tokens
    $template = $template -replace '\{\{WORKSPACE_ID\}\}', $WorkspaceResourceId
    $template = $template -replace '\{\{WORKBOOK_NAME\}\}', $WorkbookName
    $template = $template -replace '\{\{DEPLOY_DATE\}\}', (Get-Date -Format "yyyy-MM-dd")

    # Replace custom parameters
    foreach ($key in $Parameters.Keys) {
        $template = $template -replace "\{\{$key\}\}", $Parameters[$key]
    }

    # Parse and deploy
    $workbookContent = $template | ConvertFrom-Json
    $workbookId = [guid]::NewGuid().ToString()

    $body = @{
        location   = (Get-AzResourceGroup -Name $ResourceGroup).Location
        kind       = "shared"
        tags       = @{ "hidden-title" = $WorkbookName; "deployed-by" = "secops-squad" }
        properties = @{
            displayName    = $WorkbookName
            category       = "sentinel"
            sourceId       = $WorkspaceResourceId
            version        = "Notebook/1.0"
            serializedData = ($workbookContent | ConvertTo-Json -Depth 50 -Compress)
        }
    } | ConvertTo-Json -Depth 10

    $uri = "https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Insights/workbooks/{2}?api-version=2022-04-01" -f
        (Get-AzContext).Subscription.Id, $ResourceGroup, $workbookId

    $result = Invoke-AzRestMethod -Method PUT -Uri $uri -Payload $body
    if ($result.StatusCode -eq 200 -or $result.StatusCode -eq 201) {
        Write-Host "Workbook deployed: $WorkbookName ($workbookId)" -ForegroundColor Green
        return ($result.Content | ConvertFrom-Json)
    } else {
        Write-Error "Deploy failed: $($result.StatusCode) — $($result.Content)"
    }
}
```

### KQL Query Injection

Inject KQL queries into workbook items dynamically:

```powershell
function Set-WorkbookQuery {
    param(
        [object]$WorkbookContent,
        [string]$ItemName,
        [string]$KqlQuery
    )

    $item = $WorkbookContent.items | Where-Object { $_.name -eq $ItemName }
    if (-not $item) {
        Write-Error "Item '$ItemName' not found in workbook"
        return $WorkbookContent
    }

    # Escape newlines for JSON serialization
    $escapedQuery = $KqlQuery -replace "`n", "\n" -replace "`r", ""
    $item.content.query = $escapedQuery
    return $WorkbookContent
}

# Usage: swap query in a workbook template
$workbook = Get-Content "templates/soc-dashboard.json" | ConvertFrom-Json
$workbook = Set-WorkbookQuery -WorkbookContent $workbook -ItemName "severity-chart" -KqlQuery @"
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status != 'Closed'
| summarize Count=count() by Severity
| order by Count desc
"@
```

### Conditional Visibility

Show or hide workbook items based on parameter values:

```json
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "SecurityIncident\n| where Severity == 'High'\n| where Status == 'New'\n| take 20",
    "title": "Critical Incidents (High Severity Only)",
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces",
    "visualization": "table"
  },
  "conditionalVisibility": {
    "parameterName": "ShowHighOnly",
    "comparison": "isEqualTo",
    "value": "true"
  },
  "name": "high-severity-only"
}
```

### Cross-Workspace Workbook

Query across multiple workspaces using the `workspace()` function:

```json
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "union\n  (workspace('{PrimaryWorkspace}').SecurityIncident | where TimeGenerated > ago(7d)),\n  (workspace('{SecondaryWorkspace}').SecurityIncident | where TimeGenerated > ago(7d))\n| summarize Count=count() by WorkspaceName=TenantId, Severity\n| order by Count desc",
    "size": 0,
    "title": "Cross-Workspace Incident Summary",
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces",
    "crossComponentResources": ["{PrimaryWorkspace}", "{SecondaryWorkspace}"],
    "visualization": "barchart"
  },
  "name": "cross-workspace-incidents"
}
```

---

## CRUD Operations

### Create Workbook

```powershell
function New-SentinelWorkbook {
    param(
        [Parameter(Mandatory)]
        [string]$DisplayName,

        [Parameter(Mandatory)]
        [string]$WorkspaceResourceId,

        [Parameter(Mandatory)]
        [string]$ResourceGroup,

        [Parameter(Mandatory)]
        [object]$SerializedContent,

        [string]$Category = "sentinel"
    )

    $workbookId = [guid]::NewGuid().ToString()
    $subscriptionId = (Get-AzContext).Subscription.Id

    $body = @{
        location   = (Get-AzResourceGroup -Name $ResourceGroup).Location
        kind       = "shared"
        tags       = @{
            "hidden-title" = $DisplayName
            "deployed-by"  = "secops-squad-herc"
            "deployed-at"  = (Get-Date).ToUniversalTime().ToString("o")
        }
        properties = @{
            displayName    = $DisplayName
            category       = $Category
            sourceId       = $WorkspaceResourceId
            version        = "Notebook/1.0"
            serializedData = ($SerializedContent | ConvertTo-Json -Depth 50 -Compress)
        }
    } | ConvertTo-Json -Depth 10

    $uri = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${workbookId}?api-version=2022-04-01"
    $result = Invoke-AzRestMethod -Method PUT -Path $uri -Payload $body

    if ($result.StatusCode -in 200, 201) {
        $created = $result.Content | ConvertFrom-Json
        return @{ ok = $true; data = $created; id = $workbookId }
    } else {
        return @{ ok = $false; error = $result.Content; status = $result.StatusCode }
    }
}
```

### Read Workbook

```powershell
function Get-SentinelWorkbook {
    param(
        [string]$WorkbookId,
        [string]$ResourceGroup,
        [switch]$IncludeContent
    )

    $subscriptionId = (Get-AzContext).Subscription.Id
    $uri = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${WorkbookId}?api-version=2022-04-01"

    $result = Invoke-AzRestMethod -Method GET -Path $uri
    if ($result.StatusCode -eq 200) {
        $workbook = $result.Content | ConvertFrom-Json
        if ($IncludeContent) {
            $workbook | Add-Member -NotePropertyName "parsedContent" -NotePropertyValue (
                $workbook.properties.serializedData | ConvertFrom-Json
            )
        }
        return @{ ok = $true; data = $workbook }
    } else {
        return @{ ok = $false; error = $result.Content; status = $result.StatusCode }
    }
}
```

### Update Workbook

```powershell
function Update-SentinelWorkbook {
    param(
        [Parameter(Mandatory)]
        [string]$WorkbookId,

        [Parameter(Mandatory)]
        [string]$ResourceGroup,

        [object]$NewContent,
        [string]$NewDisplayName
    )

    # Fetch current workbook
    $current = Get-SentinelWorkbook -WorkbookId $WorkbookId -ResourceGroup $ResourceGroup -IncludeContent
    if (-not $current.ok) { return $current }

    $workbook = $current.data
    $properties = $workbook.properties

    if ($NewDisplayName) { $properties.displayName = $NewDisplayName }
    if ($NewContent) { $properties.serializedData = ($NewContent | ConvertTo-Json -Depth 50 -Compress) }

    $body = @{
        location   = $workbook.location
        kind       = $workbook.kind
        tags       = $workbook.tags
        properties = $properties
    } | ConvertTo-Json -Depth 10

    $subscriptionId = (Get-AzContext).Subscription.Id
    $uri = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${WorkbookId}?api-version=2022-04-01"
    $result = Invoke-AzRestMethod -Method PUT -Path $uri -Payload $body

    if ($result.StatusCode -in 200, 201) {
        return @{ ok = $true; data = ($result.Content | ConvertFrom-Json) }
    } else {
        return @{ ok = $false; error = $result.Content; status = $result.StatusCode }
    }
}
```

### Delete Workbook

```powershell
function Remove-SentinelWorkbook {
    param(
        [Parameter(Mandatory)]
        [string]$WorkbookId,

        [Parameter(Mandatory)]
        [string]$ResourceGroup
    )

    $subscriptionId = (Get-AzContext).Subscription.Id
    $uri = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${WorkbookId}?api-version=2022-04-01"

    $result = Invoke-AzRestMethod -Method DELETE -Path $uri
    if ($result.StatusCode -in 200, 204) {
        return @{ ok = $true; deleted = $WorkbookId }
    } else {
        return @{ ok = $false; error = $result.Content; status = $result.StatusCode }
    }
}
```

### List Workbooks

```powershell
function Get-SentinelWorkbooks {
    param(
        [string]$ResourceGroup,
        [string]$Category = "sentinel"
    )

    $subscriptionId = (Get-AzContext).Subscription.Id
    $uri = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks?category=$Category&api-version=2022-04-01"

    $result = Invoke-AzRestMethod -Method GET -Path $uri
    if ($result.StatusCode -eq 200) {
        $workbooks = ($result.Content | ConvertFrom-Json).value
        return @{ ok = $true; data = $workbooks; count = $workbooks.Count }
    } else {
        return @{ ok = $false; error = $result.Content; status = $result.StatusCode }
    }
}
```

---

## Migration & Deployment

### Export and Import Between Workspaces

```powershell
function Export-SentinelWorkbook {
    param(
        [string]$WorkbookId,
        [string]$ResourceGroup,
        [string]$OutputPath
    )

    $workbook = Get-SentinelWorkbook -WorkbookId $WorkbookId -ResourceGroup $ResourceGroup -IncludeContent
    if (-not $workbook.ok) {
        Write-Error "Failed to export: $($workbook.error)"
        return
    }

    $export = @{
        metadata = @{
            displayName  = $workbook.data.properties.displayName
            category     = $workbook.data.properties.category
            exportedAt   = (Get-Date).ToUniversalTime().ToString("o")
            exportedBy   = "secops-squad-herc"
            sourceRegion = $workbook.data.location
        }
        content = $workbook.data.parsedContent
    }

    $export | ConvertTo-Json -Depth 50 | Out-File $OutputPath -Encoding UTF8
    Write-Host "Exported: $OutputPath" -ForegroundColor Green
}

function Import-SentinelWorkbook {
    param(
        [string]$ImportPath,
        [string]$TargetWorkspaceResourceId,
        [string]$TargetResourceGroup,
        [string]$NewDisplayName
    )

    $import = Get-Content $ImportPath -Raw | ConvertFrom-Json
    $displayName = if ($NewDisplayName) { $NewDisplayName } else { $import.metadata.displayName }

    $result = New-SentinelWorkbook `
        -DisplayName $displayName `
        -WorkspaceResourceId $TargetWorkspaceResourceId `
        -ResourceGroup $TargetResourceGroup `
        -SerializedContent $import.content

    if ($result.ok) {
        Write-Host "Imported: $displayName → $TargetResourceGroup" -ForegroundColor Green
    } else {
        Write-Error "Import failed: $($result.error)"
    }
    return $result
}
```

### CI/CD Pipeline for Workbook Deployment

Store workbook JSON in your repo and deploy on merge:

```yaml
# .github/workflows/deploy-workbooks.yml
name: Deploy Sentinel Workbooks

on:
  push:
    branches: [main]
    paths: ['workbooks/**/*.json']

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Azure Login
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Deploy Workbooks
        uses: azure/powershell@v2
        with:
          azPSVersion: latest
          inlineScript: |
            $workbookFiles = Get-ChildItem "workbooks/*.json" -Recurse
            foreach ($file in $workbookFiles) {
              $config = Get-Content $file.FullName -Raw | ConvertFrom-Json
              $workbookId = $config.metadata.workbookId

              # Idempotent: PUT creates or replaces
              $body = @{
                location   = "${{ vars.AZURE_LOCATION }}"
                kind       = "shared"
                tags       = @{
                  "hidden-title" = $config.metadata.displayName
                  "deployed-by"  = "github-actions"
                  "commit"       = "${{ github.sha }}"
                }
                properties = @{
                  displayName    = $config.metadata.displayName
                  category       = $config.metadata.category ?? "sentinel"
                  sourceId       = "${{ vars.WORKSPACE_RESOURCE_ID }}"
                  version        = "Notebook/1.0"
                  serializedData = ($config.content | ConvertTo-Json -Depth 50 -Compress)
                }
              } | ConvertTo-Json -Depth 10

              $uri = "/subscriptions/${{ secrets.AZURE_SUBSCRIPTION_ID }}/resourceGroups/${{ vars.RESOURCE_GROUP }}/providers/Microsoft.Insights/workbooks/${workbookId}?api-version=2022-04-01"
              $result = Invoke-AzRestMethod -Method PUT -Path $uri -Payload $body

              if ($result.StatusCode -in 200, 201) {
                Write-Host "✅ Deployed: $($config.metadata.displayName)"
              } else {
                Write-Error "❌ Failed: $($config.metadata.displayName) — $($result.StatusCode)"
                exit 1
              }
            }
```

### Version Control Patterns

```
workbooks/
├── soc-overview/
│   ├── metadata.json          # displayName, category, workbookId (stable GUID)
│   ├── content.json           # serializedData content (version-controlled)
│   └── CHANGELOG.md           # what changed per version
├── compliance-dashboard/
│   ├── metadata.json
│   ├── content.json
│   └── CHANGELOG.md
└── incident-metrics/
    ├── metadata.json
    ├── content.json
    └── CHANGELOG.md
```

**Metadata file pattern:**

```json
{
  "workbookId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "displayName": "SOC Incident Overview",
  "category": "sentinel",
  "version": "2.1.0",
  "author": "Herc",
  "lastModified": "2026-04-30"
}
```

### Multi-Workspace Deployment

Deploy the same workbook to N workspaces from `.secops/` configuration:

```powershell
function Deploy-WorkbookToAllWorkspaces {
    param(
        [string]$WorkbookDir,
        [string]$SecOpsPath = ".secops"
    )

    $metadata = Get-Content "$WorkbookDir/metadata.json" -Raw | ConvertFrom-Json
    $content  = Get-Content "$WorkbookDir/content.json" -Raw | ConvertFrom-Json

    # Load all workspaces from .secops/
    $workspaceFiles = Get-ChildItem "$SecOpsPath/workspaces/*.yaml" |
        Where-Object { $_.Name -ne "README.md" }

    $results = @()
    foreach ($wsFile in $workspaceFiles) {
        $wsConfig = Get-Content $wsFile.FullName -Raw | ConvertFrom-Yaml
        $wsResourceId = $wsConfig.workspace.id
        $wsRg = $wsConfig.workspace.resource_group

        if (-not $wsResourceId -or -not $wsRg) {
            Write-Warning "Skipping $($wsFile.Name) — missing workspace ID or resource group"
            continue
        }

        # Check data residency before deploying
        $requirements = Get-Content "$SecOpsPath/compliance/requirements.yaml" -Raw | ConvertFrom-Yaml
        $wsRegion = $wsConfig.workspace.region
        if ($requirements.data_residency.prohibited_regions -contains $wsRegion) {
            Write-Warning "Skipping $($wsConfig.workspace.name) — region $wsRegion is prohibited"
            continue
        }

        # Deploy with workspace-specific GUID (deterministic per workspace)
        $workbookId = [guid]::NewGuid().ToString()

        $result = New-SentinelWorkbook `
            -DisplayName "$($metadata.displayName) — $($wsConfig.workspace.name)" `
            -WorkspaceResourceId $wsResourceId `
            -ResourceGroup $wsRg `
            -SerializedContent $content

        $results += @{
            Workspace = $wsConfig.workspace.name
            Region    = $wsRegion
            Status    = if ($result.ok) { "Deployed" } else { "Failed" }
            Error     = if (-not $result.ok) { $result.error } else { $null }
        }
    }

    $results | ForEach-Object { [PSCustomObject]$_ } | Format-Table -AutoSize
}
```

---

## Agent Workflows

### SOC Dashboard Deployment

End-to-end workflow: template → customize → deploy → validate.

```powershell
function Deploy-SOCDashboard {
    param(
        [string]$WorkspaceResourceId,
        [string]$ResourceGroup,
        [string]$DashboardTemplate = "templates/workbooks/soc-overview.json"
    )

    Write-Host "=== SOC Dashboard Deployment ===" -ForegroundColor Cyan

    # Step 1: Load template
    Write-Host "[1/4] Loading template..." -ForegroundColor Yellow
    $template = Get-Content $DashboardTemplate -Raw | ConvertFrom-Json

    # Step 2: Customize for target workspace
    Write-Host "[2/4] Customizing for workspace..." -ForegroundColor Yellow
    $customized = $template.content
    # Inject workspace-specific parameters if needed

    # Step 3: Deploy
    Write-Host "[3/4] Deploying workbook..." -ForegroundColor Yellow
    $result = New-SentinelWorkbook `
        -DisplayName $template.metadata.displayName `
        -WorkspaceResourceId $WorkspaceResourceId `
        -ResourceGroup $ResourceGroup `
        -SerializedContent $customized

    if (-not $result.ok) {
        Write-Error "Deployment failed: $($result.error)"
        return $result
    }

    # Step 4: Validate
    Write-Host "[4/4] Validating deployment..." -ForegroundColor Yellow
    $validation = Get-SentinelWorkbook -WorkbookId $result.id -ResourceGroup $ResourceGroup
    if ($validation.ok) {
        Write-Host "✅ SOC Dashboard deployed and validated" -ForegroundColor Green
        Write-Host "   ID: $($result.id)" -ForegroundColor Gray
    } else {
        Write-Warning "Deployed but validation failed — check Azure portal"
    }

    return $result
}
```

### Compliance Dashboard Generation

Combine compliance data with workbook automation:

```powershell
function Deploy-ComplianceDashboard {
    param(
        [string]$WorkspaceResourceId,
        [string]$ResourceGroup
    )

    # Build compliance-specific workbook content
    $complianceItems = @(
        # Header
        @{
            type = 1
            content = @{ json = "# Compliance Posture Dashboard\nAuto-generated by secops-squad compliance automation." }
            name = "compliance-header"
        }
        # Framework compliance summary
        @{
            type = 3
            content = @{
                version      = "KqlItem/1.0"
                query        = "SecurityRegulatoryCompliance\n| where TimeGenerated > ago(1d)\n| summarize PassedControls=countif(IsCompliant == true), FailedControls=countif(IsCompliant == false) by ComplianceStandard=RegulatoryComplianceStandardName\n| extend ComplianceRate = round(PassedControls * 100.0 / (PassedControls + FailedControls), 1)\n| sort by ComplianceRate asc"
                title        = "Framework Compliance Rates"
                queryType    = 0
                resourceType = "microsoft.operationalinsights/workspaces"
                visualization = "table"
            }
            name = "compliance-summary"
        }
        # Compliance trend over time
        @{
            type = 3
            content = @{
                version      = "KqlItem/1.0"
                query        = "SecurityRegulatoryCompliance\n| where TimeGenerated > ago(30d)\n| summarize ComplianceRate=countif(IsCompliant == true) * 100.0 / count() by bin(TimeGenerated, 1d), RegulatoryComplianceStandardName\n| render timechart"
                title        = "Compliance Trend (30 days)"
                queryType    = 0
                resourceType = "microsoft.operationalinsights/workspaces"
                visualization = "timechart"
            }
            name = "compliance-trend"
        }
        # Failed controls detail
        @{
            type = 3
            content = @{
                version      = "KqlItem/1.0"
                query        = "SecurityRegulatoryCompliance\n| where TimeGenerated > ago(1d)\n| where IsCompliant == false\n| project Framework=RegulatoryComplianceStandardName, Control=RegulatoryComplianceControlName, Assessment=RegulatoryComplianceAssessmentName, SubscriptionId\n| sort by Framework, Control"
                title        = "Non-Compliant Controls"
                queryType    = 0
                resourceType = "microsoft.operationalinsights/workspaces"
                visualization = "table"
            }
            name = "failed-controls"
        }
    )

    $workbookContent = @{
        version = "Notebook/1.0"
        items   = $complianceItems
    }

    $result = New-SentinelWorkbook `
        -DisplayName "Compliance Posture Dashboard" `
        -WorkspaceResourceId $WorkspaceResourceId `
        -ResourceGroup $ResourceGroup `
        -SerializedContent $workbookContent

    return $result
}
```

### Incident Metrics Dashboard

```powershell
function Deploy-IncidentMetricsDashboard {
    param(
        [string]$WorkspaceResourceId,
        [string]$ResourceGroup,
        [int]$SlaMinutes = 60
    )

    $metricsItems = @(
        @{
            type = 1
            content = @{ json = "# Incident Metrics & SLA Tracking\nSLA Target: $SlaMinutes minutes to first response." }
            name = "metrics-header"
        }
        # MTTR by severity
        @{
            type = 3
            content = @{
                version      = "KqlItem/1.0"
                query        = "SecurityIncident\n| where TimeGenerated > ago(30d)\n| where Status == 'Closed'\n| extend MTTR_hours = datetime_diff('hour', ClosedTime, CreatedTime)\n| summarize AvgMTTR=round(avg(MTTR_hours),1), MedianMTTR=round(percentile(MTTR_hours, 50),1), Count=count() by Severity\n| order by Severity asc"
                title        = "Mean Time to Resolve (hours) — Last 30 Days"
                queryType    = 0
                resourceType = "microsoft.operationalinsights/workspaces"
                visualization = "table"
            }
            name = "mttr-by-severity"
        }
        # SLA compliance
        @{
            type = 3
            content = @{
                version      = "KqlItem/1.0"
                query        = "SecurityIncident\n| where TimeGenerated > ago(30d)\n| extend FirstResponseMinutes = datetime_diff('minute', FirstModifiedTime, CreatedTime)\n| extend SLAMet = FirstResponseMinutes <= $SlaMinutes\n| summarize Total=count(), MetSLA=countif(SLAMet == true), MissedSLA=countif(SLAMet == false) by bin(TimeGenerated, 1d)\n| extend SLARate = round(MetSLA * 100.0 / Total, 1)\n| project TimeGenerated, SLARate\n| render timechart"
                title        = "SLA Compliance Rate (Daily)"
                queryType    = 0
                resourceType = "microsoft.operationalinsights/workspaces"
                visualization = "timechart"
            }
            name = "sla-trend"
        }
        # Analyst workload
        @{
            type = 3
            content = @{
                version      = "KqlItem/1.0"
                query        = "SecurityIncident\n| where TimeGenerated > ago(7d)\n| where isnotempty(OwnerEmail)\n| summarize Assigned=count(), Closed=countif(Status == 'Closed'), Open=countif(Status != 'Closed') by OwnerEmail\n| sort by Assigned desc\n| take 20"
                title        = "Analyst Workload — Last 7 Days"
                queryType    = 0
                resourceType = "microsoft.operationalinsights/workspaces"
                visualization = "table"
            }
            name = "analyst-workload"
        }
    )

    $workbookContent = @{
        version = "Notebook/1.0"
        items   = $metricsItems
    }

    return New-SentinelWorkbook `
        -DisplayName "Incident Metrics & SLA Dashboard" `
        -WorkspaceResourceId $WorkspaceResourceId `
        -ResourceGroup $ResourceGroup `
        -SerializedContent $workbookContent
}
```

---

## `.secops/` Integration

All workbook deployment functions read `.secops/` for workspace targets and compliance constraints:

```powershell
# Deploy all standard SOC dashboards to all configured workspaces
function Deploy-StandardDashboardSuite {
    param([string]$SecOpsPath = ".secops")

    $workspaceFiles = Get-ChildItem "$SecOpsPath/workspaces/*.yaml" |
        Where-Object { $_.Name -ne "README.md" }

    foreach ($wsFile in $workspaceFiles) {
        $ws = Get-Content $wsFile.FullName -Raw | ConvertFrom-Yaml
        $wsId = $ws.workspace.id
        $wsRg = $ws.workspace.resource_group
        $wsName = $ws.workspace.name

        if (-not $wsId) { continue }

        Write-Host "`n=== Deploying to: $wsName ===" -ForegroundColor Cyan

        # Deploy SOC overview
        Deploy-SOCDashboard -WorkspaceResourceId $wsId -ResourceGroup $wsRg

        # Deploy compliance dashboard
        Deploy-ComplianceDashboard -WorkspaceResourceId $wsId -ResourceGroup $wsRg

        # Deploy incident metrics
        Deploy-IncidentMetricsDashboard -WorkspaceResourceId $wsId -ResourceGroup $wsRg

        Write-Host "✅ All dashboards deployed to $wsName" -ForegroundColor Green
    }
}
```

---

## Cross-References

- **Compliance Mappings:** See `skills/soar/compliance-framework-mappings.md` for compliance data that feeds dashboards
- **KQL Queries:** Freamon's `skills/kql/` hunting queries can be injected into workbook items
- **Sentinel Enrichment:** Workbook grids can link to enrichment playbooks from `skills/soar/sentinel-enrichment-*.md`
- **Teams Notification:** Dashboard alerts can trigger Teams notifications via `skills/soar/teams-notification.md`
- **`.secops/` Framework:** Workspace targets from `.secops/workspaces/`, compliance constraints from `.secops/compliance/`
