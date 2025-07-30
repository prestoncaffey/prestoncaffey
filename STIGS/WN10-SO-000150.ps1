<#
.SYNOPSIS
This powershell script prevents anonymous logon users (null session connections) from listing all account names and enumerates all shared resources that can provide a map of potential points to attack the system.
.NOTES
    Author          : Preston Caffey
    LinkedIn        : https://www.linkedin.com/in/preston-caffey-364638362/
    GitHub          : github.com/prestoncaffey
    Date Created    : 7-29-25
    Last Modified   : 7-29-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000150

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

#>


$basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

Set-ItemProperty -Path $basePath -Name "auditbasedirectories" -Value 0 -Type DWord
Set-ItemProperty -Path $basePath -Name "auditbaseobjects" -Value 0 -Type DWord
Set-ItemProperty -Path $basePath -Name "Bounds" -Value ([byte[]](0x00,0x30,0x00,0x00,0x00,0x20,0x00,0x00)) -Type Binary
Set-ItemProperty -Path $basePath -Name "crashonauditfail" -Value 0 -Type DWord
Set-ItemProperty -Path $basePath -Name "fullprivilegeauditing" -Value ([byte[]](0x00)) -Type Binary
Set-ItemProperty -Path $basePath -Name "LimitBlankPasswordUse" -Value 1 -Type DWord
Set-ItemProperty -Path $basePath -Name "NoLmHash" -Value 1 -Type DWord
Set-ItemProperty -Path $basePath -Name "Security Packages" -Value ([byte[]](0x22,0x00,0x22,0x00,0x00,0x00,0x00,0x00)) -Type MultiString
Set-ItemProperty -Path $basePath -Name "Notification Packages" -Value ([byte[]](0x73,0x00,0x63,0x00,0x65,0x00,0x63,0x00,0x6c,0x00,0x69,0x00,0x00,0x00,0x00,0x00)) -Type MultiString
Set-ItemProperty -Path $basePath -Name "Authentication Packages" -Value ([byte[]](0x6d,0x00,0x73,0x00,0x76,0x00,0x31,0x00,0x5f,0x00,0x30,0x00,0x00,0x00,0x00,0x00)) -Type MultiString
Set-ItemProperty -Path $basePath -Name "LsaPid" -Value 708 -Type DWord
Set-ItemProperty -Path $basePath -Name "LsaCfgFlagsDefault" -Value 0 -Type DWord
Set-ItemProperty -Path $basePath -Name "SecureBoot" -Value 1 -Type DWord
Set-ItemProperty -Path $basePath -Name "ProductType" -Value 6 -Type DWord
Set-ItemProperty -Path $basePath -Name "disabledomaincreds" -Value 0 -Type DWord
Set-ItemProperty -Path $basePath -Name "everyoneincludesanonymous" -Value 0 -Type DWord
Set-ItemProperty -Path $basePath -Name "forceguest" -Value 0 -Type DWord
Set-ItemProperty -Path $basePath -Name "restrictanonymous" -Value 1 -Type DWord
Set-ItemProperty -Path $basePath -Name "restrictanonymoussam" -Value 1 -Type DWord

$apPath = "$basePath\AccessProviders"
New-Item -Path $apPath -Force | Out-Null
Set-ItemProperty -Path $apPath -Name "MartaExtension" -Value "ntmarta.dll"
Set-ItemProperty -Path $apPath -Name "ProviderOrder" -Value ([byte[]](0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,0x77,0x00,0x73,0x00,0x20,0x00,0x4e,0x00,0x54,0x00,0x20,0x00,0x41,0x00,0x63,0x00,0x63,0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x20,0x00,0x50,0x00,0x72,0x00,0x6f,0x00,0x76,0x00,0x69,0x00,0x64,0x00,0x65,0x00,0x72,0x00,0x00,0x00,0x00,0x00)) -Type MultiString

$ntAccessPath = "$apPath\Windows NT Access Provider"
New-Item -Path $ntAccessPath -Force | Out-Null
Set-ItemProperty -Path $ntAccessPath -Name "ProviderPath" -Value ([byte[]](0x25,0x00,0x53,0x00,0x79,0x00,0x73,0x00,0x74,0x00,0x65,0x00,0x6d,0x00,0x52,0x00,0x6f,0x00,0x6f,0x00,0x74,0x00,0x25,0x00,0x5c,0x00,0x73,0x00,0x79,0x00,0x73,0x00,0x74,0x00,0x65,0x00,0x6d,0x00,0x33,0x00,0x32,0x00,0x5c,0x00,0x6e,0x00,0x74,0x00,0x6d,0x00,0x61,0x00,0x72,0x00,0x74,0x00,0x61,0x00,0x2e,0x00,0x64,0x00,0x6c,0x00,0x6c,0x00,0x00,0x00)) -Type ExpandString

$capPath = "$basePath\CentralizedAccessPolicies"
New-Item -Path $capPath -Force | Out-Null
Set-ItemProperty -Path $capPath -Name "MaxDataSize" -Value 0 -Type DWord

$privPath = "$basePath\ComponentUpdates\Privileges"
New-Item -Path $privPath -Force | Out-Null
Set-ItemProperty -Path $privPath -Name "01F9BAE5-4C53-4339-A356-40E5B3A3E577" -Value "PrivilegeAdd;S-1-5-80-3169285310-278349998-1452333686-3865143136-4212226833;SeServiceLogonRight"
Set-ItemProperty -Path $privPath -Name "C4C85B72-59EB-4DDB-9EF0-ECF40A264FF5" -Value "PrivilegeAdd;S-1-5-80-3169285310-278349998-1452333686-3865143136-4212226833;SeSystemTimePrivilege"

$fipsPath = "$basePath\FipsAlgorithmPolicy"
New-Item -Path $fipsPath -Force | Out-Null
Set-ItemProperty -Path $fipsPath -Name "Enabled" -Value 0 -Type DWord

$msvPath = "$basePath\MSV1_0"
New-Item -Path $msvPath -Force | Out-Null
Set-ItemProperty -Path $msvPath -Name "Auth132" -Value "IISSUBA"
Set-ItemProperty -Path $msvPath -Name "NtlmMinClientSec" -Value 0x20000000 -Type DWord
Set-ItemProperty -Path $msvPath -Name "NtlmMinServerSec" -Value 0x20000000 -Type DWord
