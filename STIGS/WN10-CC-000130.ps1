<#
.SYNOPSIS
   This PowerShell script configures a Windows system to enforce centralized control over software installations by modifying a specific registry setting.

.NOTES
    Author          : Preston Caffey
    LinkedIn        : https://www.linkedin.com/in/preston-caffey-364638362/
    GitHub          : github.com/prestoncaffey
    Date Created    : 7-27-25
    Last Modified   : 7-27-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000310

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

#>

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force
}

New-ItemProperty -Path $registryPath -Name "EnableUserControl" -PropertyType DWord -Value 0 -Force
