<#
.SYNOPSIS
  Detects excessive failed logons from Security log (Event ID 4625).
#>

Param(
  [int]$Threshold = 10,
  [int]$Minutes = 15
)

$Since = (Get-Date).AddMinutes(-$Minutes)
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$Since}

$grouped = $events | ForEach-Object {
  $ip = ($_ | Select-Object -ExpandProperty Properties)[19].Value
  if (-not $ip) { $ip = "unknown" }
  [PSCustomObject]@{ IP=$ip; Time=$_.TimeCreated }
} | Group-Object IP | Where-Object { $_.Count -ge $Threshold }

$grouped | ForEach-Object {
  Write-Output "ALERT: $($_.Name) has $($_.Count) failed logons in last $Minutes minutes."
}
