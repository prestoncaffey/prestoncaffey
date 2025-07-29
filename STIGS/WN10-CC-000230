<#
.SYNOPSIS
   It ensures that the registry path exists and then sets the PreventOverride value to 1 (enabled),which disables users' ability to bypass SmartScreen warnings for potentially malicious websites,
enforcing stricter security controls.

.NOTES
    Author          : Preston Caffey
    LinkedIn        : https://www.linkedin.com/in/preston-caffey-364638362/
    GitHub          : github.com/prestoncaffey
    Date Created    : 7-28-25
    Last Modified   : 7-28-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000230

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

#>

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

New-ItemProperty -Path $registryPath -Name "PreventOverride" -Value 1 -PropertyType DWord -Force | Out-Null
