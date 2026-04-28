# Phishing Detection Skill

This skill provides KQL queries for detecting phishing attempts in Microsoft 365 environments.

## Prerequisites

- Microsoft Sentinel workspace with Office 365 data connector enabled
- SignInLogs and EmailEvents tables available

## Detection: Suspicious Email Forwarding Rules

Look for mailbox rules that auto-forward to external addresses.

```kql
let externalDomains = dynamic(["gmail.com", "yahoo.com", "protonmail.com"]);
OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where Parameters has "ForwardTo" or Parameters has "RedirectTo"
| extend ForwardAddress = extract(@"([\w.-]+@[\w.-]+)", 1, Parameters)
| where isnotempty(ForwardAddress)
| extend ForwardDomain = tostring(split(ForwardAddress, "@")[1])
| where ForwardDomain in (externalDomains)
| project TimeGenerated, UserId, Operation, ForwardAddress, ClientIP
```

## Detection: Credential Harvesting Page Access

Identify users who clicked links leading to known credential harvesting pages.

```kql
EmailUrlInfo
| where TimeGenerated > ago(7d)
| join kind=inner (
    EmailEvents
    | where TimeGenerated > ago(7d)
    | where DeliveryAction != "Blocked"
  ) on NetworkMessageId
| where UrlDomain has_any ("login", "signin", "verify", "secure", "account")
| where UrlDomain !endswith "microsoft.com"
  and UrlDomain !endswith "microsoftonline.com"
| summarize ClickCount = count(), Users = make_set(RecipientEmailAddress, 50)
  by UrlDomain, Url
| where ClickCount > 3
| sort by ClickCount desc
```

## Non-KQL Example

This JavaScript snippet is for reference only and should NOT be extracted:

```js
const alert = { severity: 'high', title: 'Phishing detected' };
console.log(JSON.stringify(alert));
```

## Detection: Mass Download After Compromise

```kusto
let compromisedUsers = SignInLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"
| where RiskLevelDuringSignIn in ("high", "medium")
| distinct UserPrincipalName;
OfficeActivity
| where TimeGenerated > ago(1h)
| where UserId in (compromisedUsers)
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize DownloadCount = count(), Files = make_set(SourceFileName, 100)
  by UserId, ClientIP
| where DownloadCount > 50
```

## Notes

Remember to tune thresholds based on your environment's baseline activity.
