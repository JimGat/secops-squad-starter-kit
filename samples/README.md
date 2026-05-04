# samples/ — Sample Configurations

Example configurations demonstrating the SecOps Squad Starter Kit in a realistic enterprise environment.

## Available Samples

### [secops-contoso/](secops-contoso/README.md)

A complete `.secops/` configuration for **Contoso Corp** — a fictional 12,000-employee enterprise with a mature SOC.

```
samples/secops-contoso/
├── README.md            — Detailed walkthrough ✱
└── .secops/
    ├── environment.yaml — Environment overview
    ├── workspaces/      — 3 workspaces (prod-sentinel, dev-sentinel, soc-adx)
    ├── data-sources/    — Data source map + migrations
    ├── identity/        — 2 Entra tenants + RBAC conventions
    ├── alerting/        — Alert routing + escalation tiers
    ├── compliance/      — NIST + PCI-DSS + SOC 2 requirements
    └── discovery-log.yaml
```

**Environment highlights:**
- 2 Entra tenants, 3 Azure subscriptions
- ~500 GB/day log ingestion
- Cross-cloud monitoring (AWS + GCP)
- Data tiering and active migrations

## Using Samples

1. **Copy** the `.secops/` directory to your repo root
2. **Replace** Contoso values with your environment details
3. **Validate** with `npx secops-squad doctor`

See [samples/secops-contoso/README.md](secops-contoso/README.md) for the detailed walkthrough.

## Related

- [`.secops/` Schema Reference](../docs/SECOPS_SCHEMA.md) — Complete field-level documentation
- [Integration Guide](../docs/INTEGRATION.md) — Connect to real Azure environments
