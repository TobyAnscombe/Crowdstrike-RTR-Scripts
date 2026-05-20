# Enable WFP auditing
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable

# Then monitor Security event log for Event ID 5157 (blocked connection)
# or 5156 (allowed connection)
Get-WinEvent -LogName Security | Where-Object {
  $_.Id -eq 5157 -and 
  $_.Message -match "443"
} | Select-Object -First 20 | ForEach-Object {
  $xml = [xml]$_.ToXml()
  [PSCustomObject]@{
    Time        = $_.TimeCreated
    ProcessId   = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'}).'#text'
    Application = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Application'}).'#text'
    DestIP      = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestAddress'}).'#text'
    DestPort    = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestPort'}).'#text'
  }
}
