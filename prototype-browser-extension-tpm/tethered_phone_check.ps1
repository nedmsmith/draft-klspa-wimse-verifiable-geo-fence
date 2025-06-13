<#
  tethered_phone_check.ps1
  Exit codes
    0   SUCCESS-FULL
   10   SUCCESS-PARTIAL
   20   NO-PHONE
    1   NO-PAN
    2   MISMATCH
#>

param(
    [string]$InfoFile = "$PSScriptRoot\tethered_phone_info.json"
)

# ── STEP 0 – load phone identity ────────────────────────────────────────
if (-not (Test-Path $InfoFile)) { Write-Error "JSON not found"; exit 2 }
$json        = Get-Content $InfoFile -Raw | ConvertFrom-Json
$PhoneName   = $json.name
$IdentityMAC = $json.mac_address.ToUpper()

Write-Host "`nPhone (name)    : $PhoneName"
Write-Host "Unique identity : Phone Bluetooth MAC $IdentityMAC"

# ── STEP 1 – phone discoverable? ────────────────────────────────────────
$bd12 = ($IdentityMAC -replace ':','')
$present = Get-PnpDevice -Class Bluetooth -PresentOnly |
           Where-Object InstanceId -like "*_$bd12"
if (-not $present) { Write-Host "Bluetooth scan  : NOT PRESENT"; exit 20 }
Write-Host "Bluetooth scan  : PRESENT"

# ── STEP 2 – find Up PAN NIC ────────────────────────────────────────────
$pan = Get-NetAdapter | Where-Object {
    $_.Status -eq 'Up' -and $_.InterfaceDescription -like '*Personal Area Network*'
}
if (-not $pan) { Write-Host "PAN status      : no Bluetooth-PAN NIC Up"; exit 1 }

$nic = $pan[0]
Write-Host "PAN status      : Up on '$($nic.Name)' (ifIndex=$($nic.ifIndex))"

# ── helper – canonicalise MAC (reverse + clear flag bit) ────────────────
function Canon ([string]$mac) {
    $hex = $mac -replace '[-:]',''
    $b   = $hex -split '(.{2})' | Where-Object { $_ }
    [array]::Reverse($b)
    $b[-1] = '{0:X2}' -f (([Convert]::ToInt32($b[-1],16)) -band 0xFD)
    ($b -join ':').ToUpper()
}
$CanonIdentity = Canon $IdentityMAC
$SuffixIdentity= ($CanonIdentity -split ':')[-3..-1] -join ':'

# ── helper – kick-ping until ARP entry exists ───────────────────────────
function Get-PhoneMac ([int]$idx, [string]$ip) {

    $local = (Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 |
              Select-Object -First 1 -ExpandProperty IPAddress)

    $grab = {
        Get-NetNeighbor -InterfaceIndex $idx -IPAddress $ip -ErrorAction Ignore |
        Where-Object State -in 'Reachable','Stale' |
        Select-Object -First 1 -ExpandProperty LinkLayerAddress
    }

    for ($i = 0; $i -lt 6; $i++) {
        & ping.exe -n 1 -S $local -w 500 $ip | Out-Null
        if (Get-Command Test-NetConnection -ErrorAction Ignore) {
            Test-NetConnection -ComputerName $ip -Port 80 -WarningAction SilentlyContinue | Out-Null
        }
        Start-Sleep -Milliseconds 300
        $mac = & $grab
        if ($mac) { return $mac }
    }
    return $null
}

# ── STEP 3 – evaluate PAN link ──────────────────────────────────────────
$PhoneIP = Get-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix '0.0.0.0/0' |
           Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop

$rawMac = Get-PhoneMac $nic.ifIndex $PhoneIP
if (-not $rawMac) { Write-Host "Phone MAC      : <not learned>"; exit 2 }

$rawMacColon = $rawMac -replace '-', ':'             # << NEW: colon format
$canonMac    = Canon $rawMac
$suffixMac   = ($canonMac -split ':')[-3..-1] -join ':'

Write-Host "Phone IP        : $PhoneIP"
Write-Host "Phone MAC       : $rawMacColon"
Write-Host "Canonical MAC   : $canonMac"

# ── STEP 4 – decision ──────────────────────────────────────────────────
if ($canonMac -eq $CanonIdentity) {
    Write-Host "Match type      : FULL 6-byte match (unique identity confirmed)"
    exit 0
}

if ($suffixMac -eq $SuffixIdentity) {
    Write-Host "Match type      : PARTIAL 3-byte prefix match"
    Write-Host "Collision prob  : 1 / 16 777 216  (~0.000006 %)"
    exit 10
}

Write-Host "Match type      : NONE (unique identity mismatch)"
exit 2

