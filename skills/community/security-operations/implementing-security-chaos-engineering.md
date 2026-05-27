---
title: Implementing Security Chaos Engineering
category: Security Operations
difficulty: intermediate
mitre_attack: []
products: []
author: mahipal
source_repo: mukul975/Anthropic-Cybersecurity-Skills
source_skill: implementing-security-chaos-engineering
license: Apache-2.0
version: '1.0'
nist_csf:
  - DE.CM-01
  - RS.MA-01
  - GV.OV-01
  - DE.AE-02
atlas_techniques:
  - AML.T0070
  - AML.T0066
  - AML.T0082
nist_ai_rmf:
  - MEASURE-2.7
  - MAP-5.1
  - MANAGE-2.4
tags:
  - implementing
  - security
  - chaos
  - engineering
---

# Implementing Security Chaos Engineering


## When to Use

- When deploying or configuring implementing security chaos engineering capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Design and execute security chaos experiments that intentionally break security
controls to verify that detection, alerting, and response systems work correctly.

```python
# Example: Verify detection when a security group is opened
import boto3
ec2 = boto3.client("ec2")

# Chaos experiment: temporarily add 0.0.0.0/0 rule
ec2.authorize_security_group_ingress(
    GroupId="sg-12345",
    IpProtocol="tcp", FromPort=22, ToPort=22,
    CidrIp="0.0.0.0/0",
)
# Verify: does GuardDuty/Config alert fire within SLA?
# Rollback: remove the rule after verification
```

Key experiments:
1. Open a security group and verify Config Rule alerts
2. Disable CloudTrail and verify detection time
3. Create IAM admin user and verify alert triggers
4. Simulate log pipeline failure and check monitoring gaps
5. Deploy test malware hash and verify EDR response

## Examples

```python
# Rollback function for safe experiment execution
def run_experiment(setup_fn, verify_fn, rollback_fn, timeout=300):
    try:
        setup_fn()
        result = verify_fn(timeout)
    finally:
        rollback_fn()
    return result
```
