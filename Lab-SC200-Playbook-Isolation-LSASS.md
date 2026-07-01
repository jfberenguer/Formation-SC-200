# Lab SC-200 — Playbook d'isolation sur alerte LSASS (SOAR)

Playbook **PB-Isolate-Machine-on-LSASS** : déclenché par un incident Sentinel, il
extrait l'entité **Hôte** et **isole la machine dans Microsoft Defender for Endpoint**.

## Logique du flux
1. **Déclencheur** — *Microsoft Sentinel incident* (création d'incident).
2. **Entities - Get Hosts** — récupère les hôtes de l'incident.
3. **Add comment** — trace « playbook déclenché » dans l'incident.
4. **For each hôte** :
   - **Condition** : `MdatpDeviceId` présent ?
     - **Oui** → action MDE **Isolate machine** (type `Full`) + commentaire avec l'ID d'action.
     - **Non** → commentaire « ID MDE absent » (à résoudre via *Machines - Get list of machines*).

## Prérequis et permissions
- Sentinel et le connecteur **Microsoft Defender XDR** opérationnels (les entités hôte
  portent alors `MdatpDeviceId`).
- **Identité du playbook** (Managed Identity système, déjà activée dans le modèle) avec la
  permission applicative **`Machine.Isolate`** sur l'API WindowsDefenderATP.
- Sur le groupe de ressources Sentinel : rôle **Microsoft Sentinel Responder** (ou
  Contributor) pour l'identité, afin de pouvoir commenter/mettre à jour l'incident.
- Après déploiement ARM : **autoriser les deux connexions d'API** (azuresentinel, wdatp)
  dans le portail (Logic App → *API connections* → *Authorize*).

## Déploiement
**Option A — Modèle ARM** (`PB-Isolate-Machine-LSASS.azuredeploy.json`)
- Portail → *Déployer un modèle personnalisé* → charger le fichier → groupe de ressources
  Sentinel → déployer → puis autoriser les connexions.

**Option B — Construction manuelle au designer (exercice formateur)**
1. Sentinel → *Automatisation* → *Créer* → *Playbook avec incident déclencheur*.
2. Déclencheur : **When a Microsoft Sentinel incident creation rule was triggered**.
3. Ajouter **Entities - Get Hosts** (corps = entités liées de l'incident).
4. Ajouter **For each** sur `Hosts`.
5. Dans la boucle, **Condition** `MdatpDeviceId` ≠ vide.
6. Branche *True* : connecteur **Microsoft Defender for Endpoint → Isolate machine**
   - *Machine ID* = `MdatpDeviceId`
   - *Isolation type* = `Full`
   - *Comment* = « Isolation auto - alerte LSASS - Incident <numéro> »
7. Ajouter **Add comment to incident** pour journaliser le résultat.

## Branchement à la règle d'analyse LSASS
1. Sentinel → *Automatisation* → *Créer une règle d'automatisation*.
2. **Condition** : *Nom de la règle d'analyse* = la règle LSASS (requête KQL n°3).
3. **Action** : *Exécuter le playbook* → `PB-Isolate-Machine-on-LSASS`.
4. (Recommandé en lab) ajouter une action *Changer la gravité → Élevée* et *Affecter le propriétaire*.

## Sécurité / bonnes pratiques de lab
- L'isolation est **disruptive** : ne la branche **qu'à la règle LSASS High**, jamais à une
  règle large, pour éviter d'isoler toute la flotte du lab.
- **Levée d'isolation** après l'exercice : MDE → page de l'appareil → *Release from isolation*,
  ou API `POST /api/machines/{id}/unisolate`. Prévois un 2e playbook « unisolate » pour le TP.
- Teste d'abord en **mode manuel** (bouton *Run playbook* depuis l'incident) avant d'activer
  la règle d'automatisation, pour que les stagiaires voient chaque étape.
- Pense à isoler en `Selective` plutôt que `Full` si tu veux garder le RDP/agent EDR joignable
  pendant l'investigation.
