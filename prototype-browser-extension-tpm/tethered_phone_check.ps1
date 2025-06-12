<#
EXIT CODES
 0 = at least one Bluetooth PAN NIC is Up AND its peer BD_ADDR matches target
 1 = no Bluetooth PAN NIC is Up
 2 = PAN Up but peer BD_ADDR ≠ target
#>

param(
    [string]$InfoFile = "$PSScriptRoot\tethered_phone_info.json"
)

# ── STEP 0 ─ load the JSON ----------------------------------------------------
Write-Host "STEP 0 - loading JSON"
if (-not (Test-Path $InfoFile)) { Write-Error "JSON not found."; exit 2 }

$json       = Get-Content $InfoFile -Raw | ConvertFrom-Json
$TargetMac  = ($json.mac_address).ToUpper()
$TargetName = $json.name

Write-Host "Target name : $TargetName"
Write-Host "Target MAC  : $TargetMac"
Write-Host ""

# ── STEP 1 ─ find Bluetooth PAN NICs that are Up -----------------------------
Write-Host "STEP 1 - scanning NICs that are Up and are Bluetooth PAN"
$panUp = Get-NetAdapter |
         Where-Object {
             $_.Status -eq 'Up' -and
             $_.InterfaceDescription -like '*Personal Area Network*'
         }

if (-not $panUp) {
    Write-Host "No PAN NIC is Up."
    exit 1
}

$panUp | Format-Table ifIndex, Name, PnPDeviceID
Write-Host ""

# ── STEP 2 ─ map each NIC to its ContainerId, then to BD_ADDR ---------------
Write-Host "STEP 2 - mapping each NIC to its Bluetooth device"
$owners = @()

foreach ($nic in $panUp) {

    # 2a. resolve the NIC itself to a PnP object to grab ContainerId
    $nicDev = Get-PnpDevice -InstanceId $nic.PnPDeviceID -ErrorAction SilentlyContinue
    if (-not $nicDev) { continue }

    $cid = $nicDev.ContainerId
    Write-Host "NIC '$($nic.Name)' container : $cid"

    # 2b. find Bluetooth device under the same container
    $bt = Get-PnpDevice -PresentOnly -Class Bluetooth |
          Where-Object { $_.ContainerId -eq $cid -and $_.InstanceId -match '_([0-9A-F]{12})$' } |
          Select-Object -First 1

    if ($bt) {
        $raw = $matches[1]                       # 12-hex big-endian
        $bd  = ($raw -split '(.{2})' | ? {$_}) -join ':' | ForEach-Object { $_.ToUpper() }
        Write-Host "  -> Bluetooth device BD_ADDR : $bd"
        $owners += $bd
    } else {
        Write-Host "  -> no Bluetooth device found in same container"
    }
}

Write-Host ""

# ── STEP 3 ─ decide ----------------------------------------------------------
if ($owners -contains $TargetMac) {
    Write-Host "SUCCESS: PAN Up and linked to $TargetName [$TargetMac]"
    exit 0
}

Write-Host "PAN Up but NOT linked to $TargetName [$TargetMac]"
exit 2

