# sk-enumpassive

**Énumération passive 100 % — bypass Cloudflare + reverse IP.**

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
- `subfinder`, `curl`, `jq`
- Optionnel : clés API chargées depuis `~/.config/sk-enumpassive.env`

## Clés API

Les clés ne sont **jamais** hardcodées. Crée un fichier hors git :

```bash
# ~/.config/sk-enumpassive.env  (NE PAS committer)
export VT_API_KEY="..."
export SECURITYTRAILS_API_KEY="..."
export CENSYS_API_ID="..." ; export CENSYS_API_SECRET="..."
export SHODAN_API_KEY="..."
```

Les sources gratuites fonctionnent sans aucune clé.

## Licence

MIT