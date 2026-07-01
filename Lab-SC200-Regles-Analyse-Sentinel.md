# Lab SC-200 — Règles d'analyse Sentinel (exercice KQL)

> Prérequis : connecteur **Microsoft Defender XDR** activé dans Sentinel avec le
> streaming des événements *Advanced Hunting* (tables `DeviceProcessEvents`,
> `DeviceRegistryEvents`, `DeviceEvents`).
>
> Paramètres de règle recommandés (communs) : exécuter **toutes les 5 min**, sur
> les **1 h** précédentes, regroupement en un incident par entité, **Mappage des
> entités** indiqué sous chaque requête.

---

## 1) Exécution PowerShell suspecte (cradle de téléchargement + commande encodée)
**Famille :** Scénario A, étapes 1 & 3 — Execution / Defense Evasion
**MITRE :** T1059.001, T1027 — **Sévérité :** Medium

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("powershell.exe","pwsh.exe","powershell_ise.exe")
| where ProcessCommandLine has_any (
    "DownloadFile","DownloadString","DownloadData","Net.WebClient",
    "Invoke-WebRequest","IEX","Invoke-Expression",
    "-enc","-EncodedCommand","FromBase64String","-w hidden","-WindowStyle Hidden")
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, DeviceId, ReportId
| order by Timestamp desc
```
**Entités :** Host=`DeviceName` (HostName) · Account=`AccountName` (Name) · Process=`ProcessCommandLine` (CommandLine)

---

## 2) Séquence de reconnaissance (exploration)
**Famille :** Scénario A étape 5 & Scénario B étape 3 — Discovery
**MITRE :** T1087, T1082, T1016, T1018, T1482 — **Sévérité :** Medium
Logique : ≥ 4 commandes de reconnaissance distinctes sur un même appareil dans la fenêtre.

```kql
let lookback = 1h;
let recon = dynamic(["whoami","net user","net group","net localgroup","nltest",
                     "systeminfo","ipconfig /all","net view","quser","query user",
                     "net accounts","dsquery"]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has_any (recon)
| summarize Commandes = make_set(ProcessCommandLine, 25),
            NbDistinct = dcount(ProcessCommandLine),
            Debut = min(Timestamp), Fin = max(Timestamp)
        by DeviceId, DeviceName, AccountName
| where NbDistinct >= 4
| order by NbDistinct desc
```
**Entités :** Host=`DeviceName` (HostName) · Account=`AccountName` (Name)

---

## 3) Accès à LSASS via comsvcs.dll (vol d'identifiants)
**Famille :** Scénario B étape 2 — Credential Access
**MITRE :** T1003.001 — **Sévérité :** High

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where (FileName =~ "rundll32.exe" and ProcessCommandLine has "comsvcs"
         and ProcessCommandLine has_any ("MiniDump","#24"))
     or (ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| order by Timestamp desc
```
**Entités :** Host=`DeviceName` (HostName) · Account=`AccountName` (Name) · Process=`ProcessCommandLine` (CommandLine)

---

## 4) Sabotage de Microsoft Defender (tampering / exclusions)
**Famille :** Scénario B étape 1 — Defense Evasion
**MITRE :** T1562.001 — **Sévérité :** High

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where ProcessCommandLine has_any ("Set-MpPreference","Add-MpPreference")
| where ProcessCommandLine has_any (
    "DisableRealtimeMonitoring","DisableBehaviorMonitoring","DisableIOAVProtection",
    "DisableScriptScanning","ExclusionPath","ExclusionProcess","ExclusionExtension")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, DeviceId, ReportId
| order by Timestamp desc
```
**Entités :** Host=`DeviceName` (HostName) · Account=`AccountName` (Name) · Process=`ProcessCommandLine` (CommandLine)

---

## Bonus) Persistance par clé Run (Registre)
**Famille :** Scénario A étape 4 — Persistence
**MITRE :** T1547.001 — **Sévérité :** Medium

```kql
DeviceRegistryEvents
| where Timestamp > ago(1h)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\CurrentVersion\Run"
| where RegistryValueData has_any ("powershell","-w hidden","DownloadString",
                                   "IEX","-enc","mshta","cmd.exe /c","rundll32")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| order by Timestamp desc
```
**Entités :** Host=`DeviceName` (HostName) · Process=`InitiatingProcessCommandLine` (CommandLine)
