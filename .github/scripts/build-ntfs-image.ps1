# Builds an NTFS disk image that carries EVTX files under
# Windows\System32\winevt\Logs, the way a system drive does, so parse-image
# can be exercised in CI without a multi-GB download. Needs an elevated
# Windows session (GitHub's Windows runners are).
#
#   -Format raw   fixed VHD created by diskpart, footer stripped (a raw disk)
#   -Format vhd   VHD, -Type fixed or expandable (dynamic)
#   -Format vhdx  VHDX, -Type fixed or expandable (dynamic)
param(
    [Parameter(Mandatory = $true)][string]$Samples,
    [Parameter(Mandatory = $true)][string]$Out,
    [ValidateSet('raw', 'vhd', 'vhdx')][string]$Format = 'raw',
    [ValidateSet('fixed', 'expandable')][string]$Type = 'fixed',
    [int]$SizeMB = 160
)
$ErrorActionPreference = 'Stop'
$Out = [System.IO.Path]::GetFullPath($Out)
$disk = if ($Format -eq 'raw') { [System.IO.Path]::ChangeExtension($Out, '.vhd') } else { $Out }
if ($Format -eq 'raw') { $Type = 'fixed' }
Remove-Item $disk, $Out -ErrorAction SilentlyContinue
$letter = 'X'
@"
create vdisk file="$disk" maximum=$SizeMB type=$Type
select vdisk file="$disk"
attach vdisk
create partition primary
format fs=ntfs label="MASSTIN" quick
assign letter=$letter
"@ | Out-File -Encoding ascii "$env:TEMP\masstin-diskpart.txt"
diskpart /s "$env:TEMP\masstin-diskpart.txt" | Out-Null
Start-Sleep 2
$logs = "${letter}:\Windows\System32\winevt\Logs"
New-Item -ItemType Directory -Force $logs | Out-Null
$n = 0
Get-ChildItem -Path $Samples -Recurse -Filter *.evtx | ForEach-Object {
    # one flat Logs folder, as on a real system; duplicate names get a suffix
    $dst = Join-Path $logs $_.Name
    $i = 1
    while (Test-Path $dst) { $dst = Join-Path $logs ("{0}_{1}{2}" -f $_.BaseName, $i, $_.Extension); $i++ }
    Copy-Item $_.FullName $dst
    $n++
}
Write-Host "copied $n EVTX files into $logs"
@"
select vdisk file="$disk"
detach vdisk
"@ | Out-File -Encoding ascii "$env:TEMP\masstin-diskpart2.txt"
diskpart /s "$env:TEMP\masstin-diskpart2.txt" | Out-Null
if ($Format -eq 'raw') {
    # a fixed VHD is the raw disk followed by a 512-byte footer
    $len = (Get-Item $disk).Length
    $fs = [System.IO.File]::OpenRead($disk); $fo = [System.IO.File]::Create($Out)
    $buf = New-Object byte[] (1MB); $left = $len - 512
    while ($left -gt 0) { $r = $fs.Read($buf, 0, [Math]::Min($buf.Length, $left)); $fo.Write($buf, 0, $r); $left -= $r }
    $fo.Close(); $fs.Close()
    Remove-Item $disk
}
Write-Host "$Format ($Type): $Out ($((Get-Item $Out).Length) bytes)"
