# Capture SYN_SENT state connections - these are outbound attempts
# that haven't established yet
while ($true) {
  $syns = Get-NetTCPConnection -State SynSent -EA SilentlyContinue
  if ($syns) {
    foreach ($s in $syns) {
      $proc = Get-Process -Id $s.OwningProcess -EA SilentlyContinue
      $cim  = Get-CimInstance Win32_Process -Filter "ProcessId=$($s.OwningProcess)" -EA SilentlyContinue
      $owner = if ($cim) { (Invoke-CimMethod -InputObject $cim -MethodName GetOwner -EA SilentlyContinue).User } else { $null }
      [PSCustomObject]@{
        Timestamp   = Get-Date -Format 'HH:mm:ss.fff'
        RemoteIP    = $s.RemoteAddress
        RemotePort  = $s.RemotePort
        PID         = $s.OwningProcess
        ProcessName = $proc.Name
        ProcessPath = $proc.MainModule.FileName
        CommandLine = $cim.CommandLine
        RunningAs   = $owner
        ParentPID   = $cim.ParentProcessId
        ParentName  = (Get-Process -Id $cim.ParentProcessId -EA SilentlyContinue).Name
      }
    }
  }
  Start-Sleep -Milliseconds 100
} | Tee-Object C:\Temp\syn_catch.txt
