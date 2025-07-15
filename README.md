# Intune Java Prevention Policy - Complete Implementation Guide

## Overview
This guide provides a comprehensive solution to prevent Java installation on organization devices managed by Microsoft Intune. The solution includes multiple layers of protection using application control policies, PowerShell scripts, and registry modifications.

## Components Included
- PowerShell detection and remediation scripts
- Application control policies (Win32 App restrictions)
- Registry-based blocking mechanisms
- Compliance policy configurations
- Monitoring and reporting scripts

## Prerequisites
- Microsoft Intune licensing
- Azure AD Premium P1 or P2
- Windows 10/11 devices enrolled in Intune
- Administrative access to Microsoft Endpoint Manager admin center

## Implementation Strategy

### Phase 1: Detection and Inventory
First, we'll identify existing Java installations across your environment.

### Phase 2: Prevention Policies
Implement multiple blocking mechanisms to prevent new installations.

### Phase 3: Monitoring and Compliance
Set up ongoing monitoring to ensure policy effectiveness.

---

## Script Files

### 1. Java Detection Script
**File: `Detect-JavaInstallation.ps1`**

```powershell
<#
.SYNOPSIS
    Detects Java installations on Windows devices for Intune compliance
.DESCRIPTION
    This script scans for Java installations and reports compliance status
.NOTES
    Author: IT Security Team
    Version: 1.0
    Exit Codes: 0 = Compliant (No Java), 1 = Non-compliant (Java found)
#>

# Initialize variables
$JavaFound = $false
$JavaInstallations = @()

# Check common Java installation paths
$JavaPaths = @(
    "${env:ProgramFiles}\Java",
    "${env:ProgramFiles(x86)}\Java",
    "${env:ProgramFiles}\Oracle\Java",
    "${env:ProgramFiles(x86)}\Oracle\Java"
)

# Check registry for Java installations
$RegistryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

# Function to check file system paths
foreach ($Path in $JavaPaths) {
    if (Test-Path $Path) {
        $JavaFound = $true
        $JavaInstallations += "File System: $Path"
        Write-Host "Java installation found at: $Path"
    }
}

# Function to check registry entries
foreach ($RegPath in $RegistryPaths) {
    if (Test-Path $RegPath) {
        $SubKeys = Get-ChildItem -Path $RegPath -ErrorAction SilentlyContinue
        foreach ($SubKey in $SubKeys) {
            $DisplayName = (Get-ItemProperty -Path $SubKey.PSPath -Name "DisplayName" -ErrorAction SilentlyContinue).DisplayName
            if ($DisplayName -like "*Java*" -or $DisplayName -like "*JRE*" -or $DisplayName -like "*JDK*") {
                $JavaFound = $true
                $JavaInstallations += "Registry: $DisplayName"
                Write-Host "Java installation found in registry: $DisplayName"
            }
        }
    }
}

# Check for Java executables in PATH
$JavaExecutables = @("java.exe", "javac.exe", "javaw.exe")
foreach ($Executable in $JavaExecutables) {
    $JavaExe = Get-Command $Executable -ErrorAction SilentlyContinue
    if ($JavaExe) {
        $JavaFound = $true
        $JavaInstallations += "PATH: $($JavaExe.Source)"
        Write-Host "Java executable found in PATH: $($JavaExe.Source)"
    }
}

# Return compliance status
if ($JavaFound) {
    Write-Host "COMPLIANCE: NON-COMPLIANT - Java installations detected"
    Write-Host "Installations found: $($JavaInstallations -join '; ')"
    exit 1
} else {
    Write-Host "COMPLIANCE: COMPLIANT - No Java installations detected"
    exit 0
}
```

### 2. Java Remediation Script
**File: `Remediate-JavaInstallation.ps1`**

```powershell
<#
.SYNOPSIS
    Removes Java installations and prevents future installations
.DESCRIPTION
    This script removes existing Java installations and implements prevention measures
.NOTES
    Author: IT Security Team
    Version: 1.0
    Exit Codes: 0 = Success, 1 = Failure
#>

# Initialize variables
$RemediationSuccess = $true
$LogFile = "$env:TEMP\JavaRemediation.log"

# Function to write to log
function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Host $Message
}

Write-Log "Starting Java remediation process..."

# Uninstall Java via WMI
try {
    $JavaPrograms = Get-WmiObject -Class Win32_Product | Where-Object { 
        $_.Name -like "*Java*" -or $_.Name -like "*JRE*" -or $_.Name -like "*JDK*" 
    }
    
    foreach ($Program in $JavaPrograms) {
        Write-Log "Attempting to uninstall: $($Program.Name)"
        $Program.Uninstall() | Out-Null
        Write-Log "Successfully uninstalled: $($Program.Name)"
    }
} catch {
    Write-Log "Error during WMI uninstallation: $($_.Exception.Message)"
    $RemediationSuccess = $false
}

# Remove Java directories
$JavaDirectories = @(
    "${env:ProgramFiles}\Java",
    "${env:ProgramFiles(x86)}\Java",
    "${env:ProgramFiles}\Oracle\Java",
    "${env:ProgramFiles(x86)}\Oracle\Java"
)

foreach ($Directory in $JavaDirectories) {
    if (Test-Path $Directory) {
        try {
            Remove-Item -Path $Directory -Recurse -Force
            Write-Log "Removed directory: $Directory"
        } catch {
            Write-Log "Failed to remove directory: $Directory - $($_.Exception.Message)"
            $RemediationSuccess = $false
        }
    }
}

# Implement registry-based blocking
try {
    # Block Java installers via Software Restriction Policies
    $SRPPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
    
    if (!(Test-Path $SRPPath)) {
        New-Item -Path $SRPPath -Force | Out-Null
    }
    
    # Set default security level to unrestricted for everything except Java
    Set-ItemProperty -Path $SRPPath -Name "DefaultLevel" -Value 262144 -Type DWord
    
    # Create path rule to block Java installers
    $PathRulePath = "$SRPPath\0\Paths\{12345678-1234-1234-1234-123456789012}"
    New-Item -Path $PathRulePath -Force | Out-Null
    Set-ItemProperty -Path $PathRulePath -Name "Description" -Value "Block Java Installers"
    Set-ItemProperty -Path $PathRulePath -Name "SaferFlags" -Value 0 -Type DWord
    Set-ItemProperty -Path $PathRulePath -Name "ItemData" -Value "*java*setup*.exe;*java*install*.exe;*jre*.exe;*jdk*.exe"
    Set-ItemProperty -Path $PathRulePath -Name "ItemSize" -Value 0 -Type DWord
    
    Write-Log "Successfully implemented registry-based Java blocking"
} catch {
    Write-Log "Error implementing registry blocking: $($_.Exception.Message)"
    $RemediationSuccess = $false
}

# Clean up environment variables
try {
    # Remove JAVA_HOME if it exists
    [Environment]::SetEnvironmentVariable("JAVA_HOME", $null, "Machine")
    
    # Remove Java from PATH
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    $NewPath = ($CurrentPath -split ";" | Where-Object { $_ -notlike "*Java*" -and $_ -notlike "*jre*" -and $_ -notlike "*jdk*" }) -join ";"
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, "Machine")
    
    Write-Log "Successfully cleaned environment variables"
} catch {
    Write-Log "Error cleaning environment variables: $($_.Exception.Message)"
    $RemediationSuccess = $false
}

# Final status
if ($RemediationSuccess) {
    Write-Log "Java remediation completed successfully"
    exit 0
} else {
    Write-Log "Java remediation completed with errors"
    exit 1
}
```

### 3. Java Installation Monitor
**File: `Monitor-JavaInstallation.ps1`**

```powershell
<#
.SYNOPSIS
    Monitors for Java installation attempts and blocks them
.DESCRIPTION
    This script runs continuously to monitor and prevent Java installations
.NOTES
    Author: IT Security Team
    Version: 1.0
#>

# Register WMI event to monitor for Java installer processes
Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName LIKE '%java%' OR ProcessName LIKE '%jre%' OR ProcessName LIKE '%jdk%'" -Action {
    $Event = $Event.SourceEventArgs.NewEvent
    $ProcessName = $Event.ProcessName
    $ProcessId = $Event.ProcessId
    
    # Log the attempt
    $LogMessage = "Java installation attempt detected: $ProcessName (PID: $ProcessId)"
    Write-EventLog -LogName "Application" -Source "Java Prevention" -EventId 1001 -EntryType Warning -Message $LogMessage
    
    # Attempt to terminate the process
    try {
        Stop-Process -Id $ProcessId -Force
        $TerminationMessage = "Successfully terminated Java installer process: $ProcessName (PID: $ProcessId)"
        Write-EventLog -LogName "Application" -Source "Java Prevention" -EventId 1002 -EntryType Information -Message $TerminationMessage
    } catch {
        $ErrorMessage = "Failed to terminate Java installer process: $ProcessName (PID: $ProcessId) - $($_.Exception.Message)"
        Write-EventLog -LogName "Application" -Source "Java Prevention" -EventId 1003 -EntryType Error -Message $ErrorMessage
    }
}

# Keep the script running
while ($true) {
    Start-Sleep -Seconds 30
}
```

---

## Configuration Files

### 1. Application Control Policy JSON
**File: `JavaBlockingPolicy.json`**

```json
{
    "displayName": "Block Java Applications",
    "description": "Prevents installation and execution of Java applications",
    "policyType": "ApplicationControl",
    "assignments": [
        {
            "target": {
                "groupAssignmentTarget": {
                    "groupId": "ALL_DEVICES_GROUP_ID"
                }
            },
            "intent": "required"
        }
    ],
    "settings": {
        "applicationControlType": "applicationGuard",
        "blockList": [
            {
                "name": "Java Runtime Environment",
                "publisher": "Oracle Corporation",
                "action": "block"
            },
            {
                "name": "Java Development Kit",
                "publisher": "Oracle Corporation", 
                "action": "block"
            },
            {
                "name": "Java SE Runtime Environment",
                "publisher": "Oracle Corporation",
                "action": "block"
            }
        ],
        "fileHashRules": [
            {
                "ruleType": "hash",
                "action": "block",
                "comment": "Block common Java installers"
            }
        ],
        "pathRules": [
            {
                "ruleType": "path",
                "path": "*\\java*.exe",
                "action": "block",
                "comment": "Block Java executables"
            },
            {
                "ruleType": "path", 
                "path": "*\\jre*.exe",
                "action": "block",
                "comment": "Block JRE installers"
            },
            {
                "ruleType": "path",
                "path": "*\\jdk*.exe", 
                "action": "block",
                "comment": "Block JDK installers"
            }
        ]
    }
}
```

### 2. Compliance Policy Configuration
**File: `JavaCompliancePolicy.json`**

```json
{
    "displayName": "Java Installation Compliance",
    "description": "Ensures devices do not have Java installed",
    "platform": "windows10AndLater",
    "assignments": [
        {
            "target": {
                "groupAssignmentTarget": {
                    "groupId": "ALL_DEVICES_GROUP_ID"
                }
            }
        }
    ],
    "scheduledActionsForRule": [
        {
            "ruleName": "PasswordRequired",
            "scheduledActionConfigurations": [
                {
                    "actionType": "block",
                    "gracePeriodHours": 24,
                    "notificationMessageCCList": [],
                    "notificationTemplateId": ""
                }
            ]
        }
    ],
    "deviceComplianceScriptRules": [
        {
            "settingName": "JavaDetection",
            "operator": "isEquals",
            "dataType": "string",
            "operand": "compliant",
            "detectionScriptId": "DETECTION_SCRIPT_ID",
            "remediationScriptId": "REMEDIATION_SCRIPT_ID"
        }
    ]
}
```

### 3. PowerShell Script Deployment Configuration
**File: `JavaPreventionScriptDeployment.json`**

```json
{
    "displayName": "Java Prevention Script Package",
    "description": "Deploys Java detection and prevention scripts",
    "publisher": "IT Security Team",
    "largeIcon": {
        "type": "image/png",
        "value": ""
    },
    "displayVersion": "1.0.0",
    "installExperience": {
        "runAsAccount": "system"
    },
    "detectionRules": [
        {
            "ruleType": "powershell",
            "scriptContent": "# Detection script content here",
            "enforceSignatureCheck": false,
            "runAs32Bit": false
        }
    ],
    "installCommandLine": "powershell.exe -ExecutionPolicy Bypass -File .\\Remediate-JavaInstallation.ps1",
    "uninstallCommandLine": "echo 'No uninstall required'",
    "applicabilityRules": [
        {
            "ruleType": "requirement",
            "operator": "greaterThanOrEqual",
            "comparisonValue": "10.0.17763.0",
            "detectionType": "version",
            "operand": "osVersion"
        }
    ]
}
```

---

## Deployment Instructions

### Step 1: Prepare the Environment

1. **Access Microsoft Endpoint Manager Admin Center**
   - Navigate to https://endpoint.microsoft.com
   - Sign in with administrative credentials

2. **Create Device Groups**
   - Go to Groups > All Groups > New Group
   - Create groups for pilot and production deployments

### Step 2: Deploy Detection and Remediation Scripts

1. **Upload Detection Script**
   - Navigate to Devices > Scripts > Platform scripts
   - Click "Add" > "Windows 10 and later"
   - Upload `Detect-JavaInstallation.ps1`
   - Configure settings:
     - Run this script using logged-on credentials: No
     - Enforce script signature check: No
     - Run script in 64-bit PowerShell: Yes

2. **Upload Remediation Script**
   - Follow similar process for `Remediate-JavaInstallation.ps1`
   - Assign to appropriate device groups

### Step 3: Configure Compliance Policy

1. **Create Compliance Policy**
   - Navigate to Devices > Compliance policies
   - Click "Create Policy"
   - Select "Windows 10 and later"
   - Configure using the JSON settings provided

2. **Configure Actions for Noncompliance**
   - Set grace period: 24 hours
   - Action: Block access to corporate resources
   - Send email to end user: Enabled

### Step 4: Deploy Application Control Policy

1. **Create App Control Policy**
   - Navigate to Endpoint security > Application control
   - Click "Create Policy"
   - Use the JSON configuration provided
   - Assign to device groups

### Step 5: Monitor and Report

1. **Set up Monitoring**
   - Deploy the monitoring script as a scheduled task
   - Configure event log monitoring
   - Set up alerts for compliance violations

2. **Create Reports**
   - Use Intune reporting to track compliance
   - Monitor for Java installation attempts
   - Generate regular compliance reports

---

## Testing and Validation

### Test Scenarios

1. **Existing Java Installation**
   - Device with Java already installed
   - Verify detection script identifies non-compliance
   - Confirm remediation script removes Java

2. **New Java Installation Attempt**
   - Attempt to install Java on clean device
   - Verify installation is blocked
   - Confirm appropriate alerts are generated

3. **Bypass Attempts**
   - Test various Java installer types
   - Verify portable Java applications are blocked
   - Test different installation paths

### Validation Steps

1. **Pre-deployment Testing**
   - Test scripts in isolated environment
   - Verify no false positives
   - Confirm remediation doesn't break other applications

2. **Pilot Deployment**
   - Deploy to small group of test devices
   - Monitor for 48 hours
   - Collect feedback and adjust as needed

3. **Production Deployment**
   - Gradual rollout to all devices
   - Monitor compliance dashboard
   - Address any issues promptly

---

## Troubleshooting Guide

### Common Issues

1. **Detection Script False Positives**
   - Review detection logic
   - Check for legitimate Java applications
   - Adjust script parameters

2. **Remediation Failures**
   - Check execution permissions
   - Verify network connectivity
   - Review error logs

3. **Policy Not Applying**
   - Confirm device group assignments
   - Check policy conflicts
   - Verify device sync status

### Log Locations

- **Script Execution Logs**: `%TEMP%\JavaRemediation.log`
- **Event Logs**: Application Log > Java Prevention
- **Intune Logs**: `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs`

### Support Commands

```powershell
# Check policy application status
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Policies"

# Force policy sync
Start-Process -FilePath "$env:ProgramFiles\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe" -ArgumentList "-RefreshPolicies"

# Check compliance status
Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Java*" }
```

---

## Security Considerations

### Best Practices

1. **Least Privilege**
   - Scripts run with system privileges only when necessary
   - Regular review of permissions

2. **Monitoring**
   - Continuous monitoring for policy violations
   - Regular compliance reporting

3. **Exception Handling**
   - Process for legitimate Java requirements
   - Documented approval workflow

### Risk Assessment

- **Low Risk**: Policy prevents most Java installations
- **Medium Risk**: Advanced users may find workarounds
- **High Risk**: Business applications requiring Java may be affected

### Mitigation Strategies

1. **Application Inventory**
   - Identify business-critical Java applications
   - Create exceptions for approved applications

2. **User Education**
   - Communicate policy to end users
   - Provide alternatives to Java-based applications

3. **Regular Review**
   - Monthly policy effectiveness review
   - Quarterly security assessment

---

## Maintenance and Updates

### Regular Tasks

1. **Monthly**
   - Review compliance reports
   - Update detection signatures
   - Check for new Java versions

2. **Quarterly**
   - Test policy effectiveness
   - Update scripts as needed
   - Review exception requests

3. **Annually**
   - Complete security assessment
   - Update documentation
   - Review business requirements

### Version Control

- Maintain versioned copies of all scripts
- Document changes and rationale
- Test updates in isolated environment

---

## Support and Documentation

### Internal Resources

- **IT Security Team**: Primary contact for policy issues
- **Endpoint Management Team**: Intune configuration support
- **Help Desk**: End-user support and exception requests

### External Resources

- **Microsoft Documentation**: Intune best practices
- **Security Communities**: Latest threat intelligence
- **Vendor Support**: Oracle Java security updates

### Change Management

All changes to this policy must follow the organization's change management process:

1. **Change Request**: Submit formal change request
2. **Impact Assessment**: Evaluate business impact
3. **Testing**: Validate changes in test environment
4. **Approval**: Obtain necessary approvals
5. **Implementation**: Deploy changes with rollback plan
6. **Monitoring**: Monitor for issues post-deployment

---

## Conclusion

This comprehensive Java prevention policy provides multiple layers of protection against unauthorized Java installations. Regular monitoring and maintenance are essential for continued effectiveness. For questions or issues, contact the IT Security Team.

**Document Version**: 1.0  
**Last Updated**: [Current Date]  
**Next Review**: [Date + 6 months]
