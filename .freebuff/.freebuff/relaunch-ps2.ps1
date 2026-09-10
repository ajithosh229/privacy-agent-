try {
    $p = Get-Process -Id 12548 -ErrorAction Stop
    $m = $p.MainModule
    Write-Output "exe=$($m.FileName)"
    Write-Output "start=$($p.StartTime)"
    Write-Output "cwd=$($p.StartTime)"  # placeholder, cwd not directly available
    Write-Output "pid=$($p.Id)"
} catch {
    Write-Output "no-access-or-dead"
}
