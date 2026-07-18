# sk_inject — Injecteur de rapport SysReptor

**Crée un rapport SysReptor directement à partir d'un fichier `.txt`
formaté en blocs `=== NOM ===`.**

## Workflow

1. Notes brutes collées dans Claude (projet « reporting »)
2. Claude génère un rapport formaté avec des blocs `=== ... ===`
3. Sauvegarde de la réponse dans un `.txt`
4. `python3 sk_injectfinal.py rapport.txt` → rapport créé dans SysReptor

## Variantes

- `sk_inject.py`     — version de base
- `sk_injectfinal.py` — version finale : nettoyage déterministe des
  séparateurs LLM et **redaction des hashs / secrets à motif
  reconnaissable** (à privilégier)

## Usage

```bash
export SYSREPTOR_TOKEN=ton_token
python3 sk_injectfinal.py rapport_formate.txt
```

## Format du `.txt` attendu

Le fichier est découpé en blocs délimités par `=== NOM ===`. Les noms de
blocs attendus (à adapter à ton template SysReptor) :

- `INFORMATIONS GÉNÉRALES` : lignes `clé: valeur`
  (Nom du client, Référence, Type d'audit, Période, Accès fournis,
  Niveau de risque global)
- `CONTACTS CLIENT`
- sections de rapport : `report.executive_summary`, `report.scope`,
  `report.scope_negative`, `report.methodology`, `report.tools`,
  `report.introduction`, `report.findings_intro`, `report.timeline`,
  `report.iocs`, `report.remediation_plan`,
  `report.residual_attack_surface`, `report.conclusion`
- un ou plusieurs blocs `FINDING REF-0001`, `FINDING REF-0002`…
  contenant les champs : `Titre`, `CWE`, `CVSS Score`, `CVSS Vecteur`,
  `Actif`, `Composant affecté`, `Root Cause`, `Description`,
  `Chaîne d'exploitation`, `Finding Evidence`, `Impact`,
  `Surface résiduelle`, `Recommandation`, `Action corrective`, `Délai`,
  `Références`

Les blocs manquants prennent la valeur `"TODO"` dans le rapport généré.

## ⚠️ Lié à un template SysReptor spécifique

Les noms de blocs ci-dessus et le `DESIGN_ID` correspondent à un **design
de rapport SysReptor précis**. Pour recréer ce design (sections, champs,
DESIGN_ID), voir **[TEMPLATE_SETUP.md](TEMPLATE_SETUP.md)** — guide pas à pas
avec la liste exacte des sections (`general`, `contacts`, `scope_section`,
`content`) et de tous les fieldnames attendus, plus un exemple de `.txt` à
tester.

Pour ta propre instance, adapte en haut du script :

- `SYSREPTOR_URL`   (par défaut `http://127.0.0.1:8000`)
- `DESIGN_ID`        (identifiant de ton template de design SysReptor)
- éventuellement les noms de blocs si ton template diffère

## Dépendances

- Python 3
- `requests`  (`pip install -r requirements.txt`)
- SysReptor accessible

## Sécurité

- Le token est lu depuis l'environnement (`SYSREPTOR_TOKEN`) — **ne jamais
  committer de `.env`**.
- `sk_injectfinal.py` redacte les hashs et secrets à motif reconnaissable
  avant envoi.

## Licence

MIT