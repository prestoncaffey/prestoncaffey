<#
.SYNOPSIS
This PowerShell script remediates the Windows 10 STIG WN10-SO-000250, which enforces a User Account Control (UAC) setting that enhances security during privilege elevation
.NOTES
    Author          : Preston Caffey
    LinkedIn        : https://www.linkedin.com/in/preston-caffey-364638362/
    GitHub          : github.com/prestoncaffey
    Date Created    : 7-30-25
    Last Modified   : 7-30-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000250

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

#>

$current = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue

if ($null -eq $current.ConsentPromptBehaviorAdmin -or $current.ConsentPromptBehaviorAdmin -ne 2) {
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "ConsentPromptBehaviorAdmin" -Value 2 -PropertyType DWord -Force
    Write-Output "Configuration applied. A restart or logoff may be necessary for full effect."
} else {
    Write-Output "ConsentPromptBehaviorAdmin is already configured correctly (2). No change needed."
}
