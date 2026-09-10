try {
    $p = Get-Process -Id 12548 -ErrorAction Stop
    $old = $p.StartInfo | Select-Object -ExpandProperty WorkingDirectory -ErrorAction SilentlyContinue
    Write-Output "cwd-via-startinfo: $old"
} catch {
    Write-Output "no-process"
}
