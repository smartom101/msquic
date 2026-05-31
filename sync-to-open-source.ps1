param(
    [Parameter(Mandatory=$true)][string]$DllPath,
    [Parameter(Mandatory=$true)][string]$LibPath,
    [Parameter(Mandatory=$true)][string]$PdbPath,
    [Parameter(Mandatory=$true)][string]$SrcIncDir
)

$DstRoot = "D:\MDIDS_GIT\open_source\msquic"
$bin  = "$DstRoot\bin"
$lib  = "$DstRoot\lib64\release"
$inc  = "$DstRoot\include"
$incW = "$DstRoot\includeWin"

Copy-Item $DllPath "$bin\msquic.dll" -Force
Write-Host "[msquic sync] msquic.dll -> $bin"

if (Test-Path $PdbPath) {
    Copy-Item $PdbPath "$bin\msquic.pdb" -Force
    Write-Host "[msquic sync] msquic.pdb -> $bin"
}

Copy-Item $LibPath "$lib\msquic.lib" -Force
Write-Host "[msquic sync] msquic.lib -> $lib"

Get-ChildItem "$SrcIncDir\*.h","$SrcIncDir\*.hpp" -ErrorAction SilentlyContinue | ForEach-Object {
    Copy-Item $_.FullName "$inc\" -Force
}
Write-Host "[msquic sync] headers -> $inc"

Copy-Item "$SrcIncDir\msquic.h"         "$incW\msquic.h"         -Force
Copy-Item "$SrcIncDir\msquic_winuser.h" "$incW\msquic_winuser.h" -Force
Write-Host "[msquic sync] Done -> $DstRoot"
