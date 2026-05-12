<#
.SYNOPSIS
    Provisioning script for Malforge Sandbox VM.
    Fixes Windows Updates, configures WinRM, and gathers telemetry.
#>

$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Starting Malforge Sandbox Provisioning..." -ForegroundColor Cyan

# 1. Fix Windows Update Service
Write-Host "[*] Attempting to repair Windows Update components..."
Stop-Service -Name wuauserv, bits, cryptsvc -Force
Rename-Item -Path "C:\Windows\SoftwareDistribution" -NewName "SoftwareDistribution.old" -Force
Start-Service -Name wuauserv, bits, cryptsvc
Write-Host "[*] Triggering Windows Update check..."
(New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()

# 2. Configure WinRM for Autonomous Access
Write-Host "[*] Configuring WinRM (Basic Auth + Unencrypted)..."
Enable-PSRemoting -Force
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# 3. Open Firewall for WinRM
Write-Host "[*] Opening Firewall for WinRM (Port 5985)..."
New-NetFirewallRule -DisplayName "Malforge Sandbox WinRM" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow -Force

# 4. Gather Telemetry
Write-Host "[*] Gathering system facts..."
$IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' }).IPAddress[0]
$OS = (Get-WmiObject Win32_OperatingSystem).Caption + " (" + (Get-WmiObject Win32_OperatingSystem).BuildNumber + ")"
$Arch = $env:PROCESSOR_ARCHITECTURE
$Defender = (Get-MpComputerStatus).AntivirusSignatureVersion
$CSC = (Get-ChildItem -Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -ErrorAction SilentlyContinue).FullName

$Telemetry = @{
    IPAddress = $IP
    OSVersion = $OS
    Architecture = $Arch
    DefenderSignature = $Defender
    CSCPath = $CSC
    Status = "READY"
}

Write-Host "`n[+] PROVISIONING COMPLETE" -ForegroundColor Green
Write-Host "--------------------------------------------------"
$Telemetry | ConvertTo-Json
Write-Host "--------------------------------------------------"
Write-Host "[!] Please paste the JSON block above back into the chat."
