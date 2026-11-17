<#
.SYNOPSIS
  Installe et enrôle un agent Wazuh Windows (PowerShell en Administrateur).
.EXAMPLE
  .\install_agent_windows.ps1 -ManagerIP 10.10.10.20 -Segment employees -AgentName PC-COMPTA-01 -Version 4.14.10-1
.NOTES
  La configuration (FIM, journaux d'événements) vient du manager via les groupes.
  Machines sans Internet : -MsiPath avec le MSI copié depuis un partage interne.
#>
param(
  [Parameter(Mandatory=$true)][string]$ManagerIP,
  [Parameter(Mandatory=$true)][ValidateSet('dmz','servers','employees')][string]$Segment,
  [Parameter(Mandatory=$true)][string]$AgentName,
  [Parameter(Mandatory=$true)][string]$Version,          # doit être <= version du manager (ex: 4.14.10-1)
  [switch]$Whodata,
  [SecureString]$RegistrationPassword,
  [string]$MsiPath = "",
  [string]$Sha256  = ""
)
$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "[FAIL] Lancer PowerShell en tant qu'Administrateur." -ForegroundColor Red; exit 1 }

if (Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue) {
  Write-Host "[WARN] Agent déjà installé : rien n'est modifié. Désinstaller d'abord pour réinstaller." -ForegroundColor Yellow; exit 0 }

foreach ($p in 1514,1515) {
  $ok = (Test-NetConnection -ComputerName $ManagerIP -Port $p -WarningAction SilentlyContinue).TcpTestSucceeded
  Write-Host "> Test-NetConnection -ComputerName $ManagerIP -Port $p"
  if (-not $ok) { Write-Host "[FAIL] $ManagerIP`:$p injoignable : le pare-feu de l'entreprise doit autoriser ce poste -> $ManagerIP TCP $p" -ForegroundColor Red; exit 1 }
  Write-Host "[ OK ] port $p joignable"
}

if (-not $RegistrationPassword) { $RegistrationPassword = Read-Host -AsSecureString "Mot de passe d'enrôlement Wazuh" }
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($RegistrationPassword)
$RegPw = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

if ($MsiPath -eq "") {
  $MsiPath = Join-Path $env:TEMP "wazuh-agent-$Version.msi"
  Write-Host "[INFO] Téléchargement de l'agent $Version"
  Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-$Version.msi" -OutFile $MsiPath
}
if ($Sha256 -ne "") {
  $h = (Get-FileHash -Algorithm SHA256 $MsiPath).Hash
  if ($h -ne $Sha256.ToUpper()) { Write-Host "[FAIL] SHA256 différent : $h" -ForegroundColor Red; exit 1 }
  Write-Host "[ OK ] SHA256 conforme"
}

$groups = "seg-$Segment,os-windows"
if ($Whodata) { $groups += ",opt-whodata" }
Write-Host "[INFO] Installation (groupes : $groups)"
$msiArgs = "/i `"$MsiPath`" /q WAZUH_MANAGER=`"$ManagerIP`" WAZUH_AGENT_NAME=`"$AgentName`" WAZUH_AGENT_GROUP=`"$groups`" WAZUH_REGISTRATION_PASSWORD=`"$RegPw`""
Write-Host "> msiexec.exe /i `"$MsiPath`" /q WAZUH_MANAGER=... WAZUH_AGENT_GROUP=$groups (mot de passe masqué)"
$p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
$RegPw = $null
if ($p.ExitCode -ne 0) {
  Write-Host "[FAIL] msiexec code $($p.ExitCode)" -ForegroundColor Red
  if ($p.ExitCode -eq 1603) { Write-Host "       1603 = erreur fatale d'installation : relancer avec /l*v $env:TEMP\wazuh-msi.log pour le détail." }
  if ($p.ExitCode -eq 1618) { Write-Host "       1618 = une autre installation est en cours : attendre puis relancer." }
  exit 1 }

Set-Service -Name "WazuhSvc" -StartupType Automatic
Start-Service -Name "WazuhSvc"
Write-Host "[INFO] Attente de la connexion (60 s max)..."
$log = "C:\Program Files (x86)\ossec-agent\ossec.log"
for ($i=0; $i -lt 30; $i++) {
  Start-Sleep 2
  if ((Test-Path $log) -and (Select-String -Path $log -Pattern "Connected to the server" -Quiet)) {
    Write-Host "[ OK ] Agent $AgentName connecté (groupes : $groups)" -ForegroundColor Green; exit 0 }
}
Write-Host "[FAIL] Pas de connexion. Dernières erreurs :" -ForegroundColor Red
if (Test-Path $log) { Select-String -Path $log -Pattern "ERROR|WARNING" | Select-Object -Last 10 | ForEach-Object { Write-Host "  | $($_.Line)" } }
Write-Host "  Causes fréquentes : mot de passe d'enrôlement, groupe absent du manager (étape 03), version agent > manager, flux 1514/1515 bloqués."
exit 1
