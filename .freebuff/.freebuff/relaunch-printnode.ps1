$code = @'
try {
    $p = Get-Process -Id 12548 -ErrorAction Stop
    $m = $p.MainModule
    if ($m) {
        $u = [System.IO.Path]::GetFullPath($m.FileName)
        Write-Output "exe=$u"
    } else {
        Write-Output "no-main-module"
    }
} catch {
    Write-Output "no-access-or-dead"
}
'@

$code | Out-File -Encoding UTF8 -FilePath "$env:TEMP\printnode3.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\printnode3.ps1"
