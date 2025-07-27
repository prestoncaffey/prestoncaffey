<#
.SYNOPSIS
   This PowerShell script modifies a specific Windows power management setting by editing the system registry. The script first checks if the registry key exists and creates it if necessary. It then sets the ACSettingIndex value to 1, which typically enables or configures a specific behavior when the system is plugged into AC power

.NOTES
    Author          : Preston Caffey
    LinkedIn        : https://www.linkedin.com/in/preston-caffey-364638362/
    GitHub          : github.com/prestoncaffey
    Date Created    : 7-26-25
    Last Modified   : 7-26-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000150

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

#>

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"

if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

New-ItemProperty -Path $regPath -Name "ACSettingIndex" -PropertyType DWord -Value 1 -Force
  
