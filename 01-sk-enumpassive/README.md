# sk-enumpassive

**Énumération passive 100 %, bypass Cloudflare + reverse IP.**

Outil de reconnaissance qui **ne contacte jamais la cible**. Toutes les
données proviennent de sources tierces (DNS passif, CT logs, API de
threat-intel, reverse-IP publiques).

## Fonctionnalités

- Sous-domaines via `subfinder`, crt.sh, DoH (port 443)
- Résolution de l'**origin réelle** derrière Cloudflare
- **Reverse IP** (HackerTarget hostsearch)
- Étiquetage hébergeur / ASN (ipinfo.io)
- Sources à clé : SecurityTrails, Censys, Shodan, VirusTotal
- Sources gratuites (sans clé) : HackerTarget, urlscan.io, ViewDNS, ipinfo
- Sortie : **un seul rapport HTML autonome**
  - `--save DIR`  : rapport HTML + .txt intermédiaires + listes reverse-IP complètes dans `DIR`
  - `--open`      : ouvrir le rapport dans le navigateur
  - `--deep`      : recherche de l'origine par sous-domaine (long, + d'API)

## Usage

```bash
./sk-enumpassive example.com
./sk-enumpassive example.com --save ./out --open
./sk-enumpassive example.com --deep
```

## Dépendances

- Bash
- `subfinder`, `curl`
  - `subfinder` : `apt install subfinder` (Kali) ou `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
- Optionnel : clés API chargées depuis `~/.config/sk-enumpassive.env`

## Clés API (optionnelles)

L'outil fonctionne **sans aucune clé** (voir plus bas). Les clés ajoutent
juste des sources : SecurityTrails, Censys, Shodan, VirusTotal. Elles ne
sont jamais hardcodées dans le script.

### Méthode 1 : fichier de config (recommandé, persistant)

Le script charge automatiquement `~/.config/sk-enumpassive.env` au démarrage
(tu n'as pas à le `source` toi-même). Crée ce fichier **hors git** :

```bash
# ~/.config/sk-enumpassive.env  (NE PAS committer)
export VT_API_KEY="..."
export SECURITYTRAILS_API_KEY="..."
export CENSYS_API_ID="..." ; export CENSYS_API_SECRET="..."
export SHODAN_API_KEY="..."
chmod 600 ~/.config/sk-enumpassive.env
```

Pour utiliser un autre chemin : `SK_ENUMPASSIVE_ENV=/chemin/vers/fichier ./sk-enumpassive ...`

### Méthode 2 : one-shot, en une ligne

```bash
VT_API_KEY="..." SHODAN_API_KEY="..." ./sk-enumpassive example.com
```

### Où obtenir les clés (toutes avec un tier gratuit)

| Source        | Inscription                                              |
|---------------|----------------------------------------------------------|
| VirusTotal    | https://www.virustotal.com/gui/my-apikey                 |
| Shodan        | https://account.shodan.io/register                       |
| SecurityTrails| https://securitytrails.com/app/account (API key)         |
| Censys        | https://search.censys.io/account/api (API ID + Secret)   |

### Sans clé

Les sources gratuites (subfinder, crt.sh, DoH Cloudflare, HackerTarget,
ViewDNS, urlscan.io, ipinfo) suffisent à produire un rapport complet.
Le pied de page du rapport affiche `VirusTotal ✗` quand la clé manque,
c'est normal.

## Licence

MIT