# Compliance

Regulatory constraints, data residency requirements, and retention policies that affect how agents operate.

## Files

| File | Purpose |
|------|---------|
| `requirements.yaml` | Data residency, regulatory frameworks, retention requirements |

## Why This Matters

Compliance constraints override agent preferences. If GDPR prohibits data export to US regions, an agent MUST NOT deploy resources or move data to US regions — even if it would be cheaper or faster.

## Key Constraints Agents Must Check

1. **Data Residency:** Before deploying any resource, check `allowed_regions` and `prohibited_regions`
2. **Retention:** Before recommending retention changes, check `retention_requirements` minimums
3. **Regulatory Frameworks:** Before designing detection rules, check if specific reporting timelines apply (e.g., NIS2 requires 24-hour incident reporting)

## Agent Behavior

- **ALWAYS check** `requirements.yaml` before any deployment or data movement recommendation
- **NEVER suggest** moving data to `prohibited_regions`
- **WARN** when proposed retention is below regulatory minimums
- **NOTE** applicable frameworks in detection rule documentation
