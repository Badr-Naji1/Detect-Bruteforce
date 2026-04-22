# Parameters
$HoursBack = 1          # How many hours back to analyze
$Threshold = 10         # Minimum failed attempts to trigger an alert

# Calculate start time
$StartTime = (Get-Date).AddHours(-$HoursBack)

Write-Host "`n[+] Scanning Security logs for Event ID 4625 from $StartTime to now..."
Write-Host "[+] Threshold: $Threshold failed attempts`n"

try {
    # Retrieve failed logon events (Event ID 4625) from Security log
    $failedEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        ID        = 4625
        StartTime = $StartTime
    } -ErrorAction Stop

    if (-not $failedEvents) {
        Write-Host "[-] No failed logon events found in the specified time window."
        exit 0
    }

    Write-Host "[+] Found $($failedEvents.Count) total failed logon events."

    # Group by source IP address (Property index 19 in the event XML)
    $grouped = $failedEvents | Group-Object -Property {
        $_.Properties[19].Value  # Source Network Address
    }

    # Filter groups that meet or exceed threshold and are not empty
    $suspiciousIPs = $grouped | Where-Object { 
        $_.Count -ge $Threshold -and -not [string]::IsNullOrEmpty($_.Name) 
    }

    if ($suspiciousIPs) {
        Write-Warning "`n[!] POTENTIAL BRUTEFORCE DETECTED!"
        Write-Warning "The following IPs have >= $Threshold failed logons in the last hour:`n"
        foreach ($ip in $suspiciousIPs) {
            Write-Host "  - $($ip.Name) : $($ip.Count) failures"
            # Optional: list a few example usernames targeted
            $targetUsers = $ip.Group | ForEach-Object { $_.Properties[5].Value } | Select-Object -Unique
            Write-Host "    Target accounts: $($targetUsers -join ', ')"
        }
        Write-Host "`nRecommendation: Investigate these IPs and consider blocking at the firewall."
    } else {
        Write-Host "[*] No IP exceeded the threshold. No bruteforce detected."
    }
}
catch {
    Write-Error "Failed to read Security log. Ensure you are running as Administrator and the log exists."
    Write-Error $_.Exception.Message
    exit 1
}
