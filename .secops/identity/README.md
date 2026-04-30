# Identity

Tenant topology and RBAC conventions for multi-tenant, MSSP, and Lighthouse environments.

## Files

| File | Purpose |
|------|---------|
| `tenants.yaml` | Multi-tenant topology with cross-tenant access |
| `rbac-conventions.yaml` | Naming patterns, role assignments, PIM config |

## Why This Matters

Agents need to know:
- **Which tenants exist** and how they relate (primary, secondary, managed, delegated)
- **Access boundaries** — Lighthouse-delegated access can't reach Entra ID in customer tenants
- **RBAC patterns** — consistent naming prevents conflicting role assignments
- **PIM conventions** — which roles require just-in-time activation

## Supported Scenarios

- **Enterprise:** Single or multi-tenant with primary/secondary tenants
- **MSSP:** Management tenant + Lighthouse-delegated customer tenants
- **CSP:** Cloud Solution Provider relationships
- **Government:** Azure Government with IL4/IL5 constraints
- **B2B:** Guest access to partner tenants

## Agent Behavior

1. Check `tenants.yaml` to understand which tenant context they're operating in
2. Check `rbac-conventions.yaml` before creating security groups or role assignments
3. For MSSP scenarios, verify Lighthouse delegation scopes before cross-tenant operations
