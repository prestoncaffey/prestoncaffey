<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Preston Caffey
    LinkedIn        : https://www.linkedin.com/in/preston-caffey-364638362/
    GitHub          : github.com/prestoncaffey
    Date Created    : 7-26-25
    Last Modified   : 7-26-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000255

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

#>

# Main System Policy Registry Path
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Create main registry key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set main system values
$values = @{
    "ConsentPromptBehaviorUser"        = 0x00000000
    "ConsentPromptBehaviorAdmin"       = 0x00000005
    "DSCAutomationHostEnabled"         = 0x00000002
    "EnableCursorSuppression"          = 0x00000001
    "EnableFullTrustStartupTasks"      = 0x00000002
    "EnableInstallerDetection"         = 0x00000001
    "EnableLUA"                        = 0x00000001
    "EnableSecureUIAPaths"            = 0x00000001
    "EnableUIADesktopToggle"          = 0x00000000
    "EnableUwpStartupTasks"           = 0x00000002
    "EnableVirtualization"            = 0x00000001
    "PromptOnSecureDesktop"           = 0x00000001
    "SupportFullTrustStartupTasks"    = 0x00000001
    "SupportUwpStartupTasks"          = 0x00000001
    "ValidateAdminCodeSignatures"     = 0x00000000
    "dontdisplaylastusername"         = 0x00000000
    "legalnoticecaption"              = ""
    "legalnoticetext"                 = ""
    "scforceoption"                   = 0x00000000
    "shutdownwithoutlogon"           = 0x00000001
    "undockwithoutlogon"             = 0x00000001
}

foreach ($name in $values.Keys) {
    New-ItemProperty -Path $regPath -Name $name -Value $values[$name] -PropertyType DWord -Force | Out-Null
}

# Override string types for legalnoticecaption and legalnoticetext
Set-ItemProperty -Path $regPath -Name "legalnoticecaption" -Value "" -Type String
Set-ItemProperty -Path $regPath -Name "legalnoticetext" -Value "" -Type String

# Create subkeys
$subkeys = @(
    "$regPath\Audit",
    "$regPath\UIPI",
    "$regPath\UIPI\Clipboard",
    "$regPath\UIPI\Clipboard\ExceptionFormats"
)

foreach ($key in $subkeys) {
    if (-not (Test-Path $key)) {
        New-Item -Path $key -Force | Out-Null
    }
}

# Set Clipboard ExceptionFormats values
$clipboardFormats = @{
    "CF_BITMAP"       = 0x00000002
    "CF_DIB"          = 0x00000008
    "CF_DIBV5"        = 0x00000011
    "CF_OEMTEXT"      = 0x00000007
    "CF_PALETTE"      = 0x00000009
    "CF_TEXT"         = 0x00000001
    "CF_UNICODETEXT"  = 0x0000000d
}

$clipboardKey = "$regPath\UIPI\Clipboard\ExceptionFormats"

foreach ($name in $clipboardFormats.Keys) {
    New-ItemProperty -Path $clipboardKey -Name $name -Value $clipboardFormats[$name] -PropertyType DWord -Force | Out-Null
}

Write-Output "Registry settings applied successfully."
