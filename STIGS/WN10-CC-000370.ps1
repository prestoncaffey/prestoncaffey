<#
.SYNOPSIS
  This PowerShell script disables the use of Windows Hello for Business PIN sign-in for domain users by setting the AllowDomainPINLogon registry value to 0

.NOTES
    Author          : Preston Caffey
    LinkedIn        : https://www.linkedin.com/in/preston-caffey-364638362/
    GitHub          : github.com/prestoncaffey
    Date Created    : 8-1-25
    Last Modified   : 7-1-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000370

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

#>
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$propertyName = "AllowDomainPINLogon"
$propertyValue = 0

If (-Not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

New-ItemProperty -Path $registryPath -Name $propertyName -Value $propertyValue -PropertyType DWord -Force
