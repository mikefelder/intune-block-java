# Block Java Installation on Organization Endpoints with Intune

## Overview

This guide provides a complete solution to prevent Microsoft 365 (M365) users from installing or running Java on organization-managed Windows endpoints. The approach leverages Microsoft Intune with Windows Defender Application Control (WDAC).

---

## Requirements

- Microsoft Intune with admin permissions
- Windows 10/11 Pro, Enterprise, or Education endpoints (WDAC compatible)
- PowerShell (for policy conversion, if needed)

---

## Solution Approach

1. **Block Java Executables** using WDAC custom policy (deployed via Intune).
2. **Optional:** Harden device permissions and block additional user-installed software using Attack Surface Reduction (ASR) rules in Intune.
3. **Optional:** Remove any existing Java installations using an Intune remediation script.

---

## Setup Instructions

### 1. Create the WDAC Policy

Use the following sample WDAC XML policy to block Java-related executables and common installer names. You can expand this list as needed.

<details>
<summary>Click to view <code>Block-Java-WDAC.xml</code></summary>

```xml
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>1.0.0.0</VersionEx>
  <PolicyTypeID>{D4C935A5-46DE-4751-B80E-FA6E7BFEFB75}</PolicyTypeID>
  <BasePolicyID>{D4C935A5-46DE-4751-B80E-FA6E7BFEFB75}</BasePolicyID>
  <PolicyName>Block Java Installation</PolicyName>
  <Enforcements>
    <EnforcementMode>Enabled</EnforcementMode>
  </Enforcements>
  <FileRules>
    <!-- Block common Java executables by file name -->
    <FileNameRule Action="Deny" FileName="java.exe" />
    <FileNameRule Action="Deny" FileName="javaw.exe" />
    <FileNameRule Action="Deny" FileName="javac.exe" />
    <FileNameRule Action="Deny" FileName="javaws.exe" />
    <!-- Block common Java installer names -->
    <FileNameRule Action="Deny" FileName="jre-*.exe" />
    <FileNameRule Action="Deny" FileName="jdk-*.exe" />
    <FileNameRule Action="Deny" FileName="java_install*.exe" />
    <FileNameRule Action="Deny" FileName="JavaSetup*.exe" />
  </FileRules>
  <SigningScenarios>
    <SigningScenario ID="ID_SIGNING_SCENARIO_WINDOWS" FriendlyName="Windows" />
  </SigningScenarios>
</SiPolicy>
```
