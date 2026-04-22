# Detect-Bruteforce
PowerShell script that scans Windows Security logs for Event ID 4625 (failed logon) and flags source IPs with 10+ failures in the last hour—a strong indicator of credential stuffing or password spraying.

## 🎯 Purpose

In a Security Operations Center (SOC), one of the first signs of an attack is a spike in failed logon attempts. This script automates the detection of such patterns by counting failed logons per source IP over a defined time window.

## 🛠️ How It Works

1. Queries the **Security** event log for Event ID **4625** (An account failed to log on).
2. Groups events by the **source IP address** (field 19 in the event).
3. Flags any IP with **10 or more failures** (configurable) within the last hour.

## 🚀 Usage

```powershell
# Run PowerShell as Administrator
.\Detect-Bruteforce.ps1
