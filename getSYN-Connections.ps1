# Capture SYN_SENT state connections - these are outbound attempts 
# that haven't established yet
while ($true) {
  $syns = Get-NetTCPConnection -State SynSent -EA SilentlyContinue
  if ($syns) {
    foreach ($s in $syns) {
      $proc = Get-Process -Id $s.OwningProcess -EA SilentlyContinue
      $wmi = Get-WmiObject Win32_Process -Filter "ProcessId=$($s.OwningProcess)" -EA SilentlyContinue
      [PSCustomObject]@{
        Timestamp   = Get-Date -Format 'HH:mm:ss.fff'
        RemoteIP    = $s.RemoteAddress
        RemotePort  = $s.RemotePort
        PID         = $s.OwningProcess
        ProcessName = $proc.Name
        ProcessPath = $proc.MainModule.FileName
        CommandLine = $wmi.CommandLine
        RunningAs   = $wmi.GetOwner().User
        ParentPID   = $wmi.ParentProcessId
        ParentName  = (Get-Process -Id $wmi.ParentProcessId -EA SilentlyContinue).Name
      }
    }
  }
  Start-Sleep -Milliseconds 100
} | Tee-Object C:\Temp\syn_catch.txt
