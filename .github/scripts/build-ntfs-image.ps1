# Builds a raw NTFS disk image that carries EVTX files under
# Windows\System32\winevt\Logs, the way a system drive does, so parse-image
# can be exercised in CI on all three operating systems without a multi-GB
# download. Needs an elevated Windows session (GitHub's Windows runners
# are): a fixed-size VHD is created with diskpart, formatted by Windows,
# filled, detached, and the raw disk is the VHD minus its 512-byte footer.
param(
    [Parameter(Mandatory = $true)][string]$Samples,
    [Parameter(Mandatory = $true)][string]$Out,
    [int]$SizeMB = 160
)
$ErrorActionPreference = 'Stop'
$Out = [System.IO.Path]::GetFullPath($Out)
$vhd = [System.IO.Path]::ChangeExtension($Out, '.vhd')
Remove-Item $vhd, $Out -ErrorAction SilentlyContinue
$letter = 'X'
@"
create vdisk file="$vhd" maximum=$SizeMB type=fixed
select vdisk file="$vhd"
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
Get-Volume -DriveLetter $letter | Select-Object FileSystem, Size, SizeRemaining | Format-Table | Out-String | Write-Host
@"
select vdisk file="$vhd"
detach vdisk
"@ | Out-File -Encoding ascii "$env:TEMP\masstin-diskpart2.txt"
diskpart /s "$env:TEMP\masstin-diskpart2.txt" | Out-Null
$len = (Get-Item $vhd).Length
$fs = [System.IO.File]::OpenRead($vhd); $fo = [System.IO.File]::Create($Out)
$buf = New-Object byte[] (1MB); $left = $len - 512
while ($left -gt 0) { $r = $fs.Read($buf, 0, [Math]::Min($buf.Length, $left)); $fo.Write($buf, 0, $r); $left -= $r }
$fo.Close(); $fs.Close()
Remove-Item $vhd
Write-Host "raw image: $Out ($((Get-Item $Out).Length) bytes)"
