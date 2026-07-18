# Setup du template SysReptor pour sk_inject

`sk_inject` ne fonctionne pas avec n'importe quel design SysReptor : il
écrit dans des **sections** précises et des **champs** précis. Cette
page explique comment recréer le design attendu (ou adapter le script à
ton propre design).

## 1. Pré-requis : SysReptor en route

```bash
# SysReptor via Docker (voir la doc officielle SysReptor)
docker run -p 8000:8000 sysreptor/sysreptor:latest
# UI  : http://127.0.0.1:8000
# API : http://127.0.0.1:8000/api/v1/
```

Crée un token d'API dans SysReptor (profil, onglet API tokens) puis :

```bash
export SYSREPTOR_TOKEN=ton_token
```

## 2. Créer le design de rapport

Dans SysReptor : **Designs, New design** (un design de type
*pentest report*). Le script attend **4 sections** avec les IDs suivants
(ces IDs doivent correspondre exactement aux `section_id` que tu vois
dans l'éditeur de design SysReptor) :

| Section ID    | Rôle                                |
|---------------|-------------------------------------|
| `general`     | Page de garde + résumé exécutif     |
| `contacts`    | Contacts client                     |
| `scope_section` | Périmètre + méthodologie + outils |
| `content`     | Corps du rapport (intro, chronologie, IOC, plan de remédiation, conclusion) |

### Champs attendus par section

Le script envoie ces `fieldnames`. Dans l'éditeur de design, ajoute à
chaque section un champ Markdown (ou texte) portant exactement ce nom :

**Section `general`**
- `title`, `client_name`, `ref`, `version`, `date`
- `audit_type`, `risk_level`, `period`, `access`
- `executive_summary`

**Section `contacts`**
- `client_contacts`

**Section `scope_section`**
- `scope`, `scope_negative`, `methodology`, `tools_used`

**Section `content`**
- `introduction`, `findings_intro`, `timeline`, `iocs`
- `remediation_plan`, `residual_attack_surface`, `conclusion`

### Champs attendus pour chaque finding

Les findings sont créés via l'API (endpoint `/findings/`). Le script envoie
ces champs :

- `title`, `finding_id`, `cvss`, `cwe_cve`
- `affected_asset`, `affected_component`
- `root_cause`, `description`, `exploitation_chain`
- `finding_evidence`, `impact`, `residual_surface`
- `recommendation`, `references` (liste d'URLs)
- `action_corrective`, `delai_remediation`

Ton design doit définir un template de finding avec ces fieldnames pour
que les valeurs injectées s'affichent.

## 3. Récupérer le DESIGN_ID

Une fois le design sauvegardé, son ID est dans l'URL de l'éditeur SysReptor
(ex : `http://127.0.0.1:8000/designs/30cb217c-.../`). Copie cet UUID et
mets-le dans le script :

```python
# en haut de sk_injectfinal.py
SYSREPTOR_URL = "http://127.0.0.1:8000"   # ton instance
DESIGN_ID     = "30cb217c-..."            # ton design ID
```

## 4. Vérifier

```bash
echo "=== INFORMATIONS GÉNÉRALES ===
Nom du client: ACME
Référence: REF-0001
Type d'audit: Boîte noire
Période: 2026-07
Accès fournis: Aucun
Niveau de risque global: ÉLEVÉ

=== report.executive_summary ===
Résumé de test.

=== FINDING REF-0001 ===
Titre: Exemple XSS réfléchi
CWE: CWE-79
CVSS Score: 6.1
CVSS Vecteur: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
Actif: https://example.com
Composant affecté: Formulaire de recherche
Root Cause: Absence d'échappement de la sortie.
Description: ... Finding Evidence: ...
Impact: ...
Recommandation: Échapper la sortie.
Action corrective: ...
Délai: 2 semaines
Références: https://owasp.org/www-community/attacks/xss/
" > /tmp/test.txt

export SYSREPTOR_TOKEN=ton_token
python3 sk_injectfinal.py /tmp/test.txt
```

Un projet + un finding doivent apparaître dans SysReptor.

## 5. Si ton design diffère

Deux options :
- **Adapter le design** aux sections/champs ci-dessus (le plus simple).
- **Adapter le script** : modifie les `section_id` dans les appels
  `update_section(...)` et les `fieldnames` des dictionnaires envoyés
  pour qu'ils collent à ton design. Les noms de blocs `=== ... ===` du
  `.txt` (côté source) peuvent rester les mêmes ; seuls les fieldnames
  côté destination SysReptor doivent correspondre.