# --------------------------- user constants ---------------------------
$MyPhoneMac = 'B8:17:C2:7A:55:66'      # <-- put YOUR iPhone’s BD_ADDR here
$PanAlias   = 'Bluetooth Network Connection*'   # wildcard covers “… 2”, “… 3”, etc.
# ---------------------------------------------------------------------

# Step 1 – is the PAN NIC up?
$pan = Get-NetAdapter -InterfaceAlias $PanAlias -ErrorAction SilentlyContinue |
       Where-Object Status -eq 'Up'

if (-not $pan) {
    Write-Output '❌  PAN adapter is not connected.'
    exit 1
}

# Step 2 – is the device on the other end OUR iPhone?
# The WMI class BTHPORT_DEVICE lists every BT Classic link that is *currently* open.
$myMacNoSep = ($MyPhoneMac -replace '[:-]', '').ToUpper()      # e.g. B817C27A5566
$targetAddr = '0x{0}' -f $myMacNoSep                          # WMI stores hex with 0x

$connected = Get-CimInstance -Namespace root\wmi -Class BTHPORT_DEVICE |
             Where-Object {
                 $_.IsConnected -and
                 $_.Address     -eq $targetAddr
             }

if ($connected) {
    Write-Output '✅  PAN is up and linked to *your* iPhone.'
    exit 0
}
else {
    Write-Output '⚠️  PAN is up but not talking to the expected phone.'
    exit 2
}
