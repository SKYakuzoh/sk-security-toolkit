#!/usr/bin/env python3
"""
SK Security - SysReptor Injector
Usage: python3 sk_inject.py rapport_formate.txt
Requires: SYSREPTOR_TOKEN dans l'environnement ou .env

Workflow :
  1. Colle tes notes brutes dans Claude.ai (projet SK Security Reporting)
  2. Claude génère le rapport formaté avec les blocs === ... ===
  3. Sauvegarde la réponse dans un fichier .txt
  4. Lance ce script -> rapport créé directement dans SysReptor
"""

import os
import sys
import json
import re
import requests
from datetime import date

# ─── CONFIG ───────────────────────────────────────────────────────────────────
SYSREPTOR_URL   = "http://127.0.0.1:8000"
DESIGN_ID       = "30cb217c-558c-4628-aea3-5e9e945844c5"
SYSREPTOR_TOKEN = os.environ.get("SYSREPTOR_TOKEN", "")

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def sysreptor_headers():
    return {
        "Authorization": f"Bearer {SYSREPTOR_TOKEN}",
        "Content-Type": "application/json",
        "X-CSRFToken": ""
    }


def sanitize(text: str) -> str:
    """Nettoyage déterministe appliqué avant parsing.
    Garantit l'absence de tirets cadratin et la redaction des hashs,
    indépendamment de ce que le LLM a produit."""

    # ── 1. Tirets cadratin / demi-cadratin ──
    # Le cadratin spacé est le marqueur LLM typique en séparateur de clause.
    text = text.replace(" — ", ", ").replace("—", ", ")
    text = text.replace(" – ", ", ").replace("–", "-")  # demi-cadratin -> trait d'union
    text = text.replace("―", "-")                         # barre horizontale

    # ── 2. Redaction déterministe des secrets à motif reconnaissable ──
    # Kerberos (AS-REP, TGS, preauth, cached creds)
    text = re.sub(r"\$krb5asrep\$[^\s]+", "[REDACTED]", text)
    text = re.sub(r"\$krb5tgs\$[^\s]+",   "[REDACTED]", text)
    text = re.sub(r"\$krb5pa\$[^\s]+",     "[REDACTED]", text)
    text = re.sub(r"\$DCC2\$[^\s]+",       "[REDACTED]", text)
    # Couple LM:NT
    text = re.sub(r"\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b", "[REDACTED]", text)
    # Hashs hex isolés, du plus long au plus court (SHA-256, SHA-1, NTLM/MD5)
    text = re.sub(r"\b[a-fA-F0-9]{64}\b", "[REDACTED]", text)
    text = re.sub(r"\b[a-fA-F0-9]{40}\b", "[REDACTED]", text)
    text = re.sub(r"\b[a-fA-F0-9]{32}\b", "[REDACTED]", text)

    return text


def parse_blocks(text: str) -> dict:
    """Parse les blocs === NOM === du fichier formaté."""
    pattern = r"===\s*(.+?)\s*===\s*\n(.*?)(?====|\Z)"
    matches = re.findall(pattern, text, re.DOTALL)
    blocks = {}
    for name, content in matches:
        blocks[name.strip()] = content.strip()
    return blocks


def parse_info(content: str) -> dict:
    """Parse les infos générales clé: valeur."""
    info = {}
    for line in content.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            info[key.strip()] = val.strip()
    return info


def parse_finding(content: str) -> dict:
    """Parse un bloc finding en dictionnaire."""
    finding = {}
    fields = [
        "Titre", "CWE", "CVSS Score", "CVSS Vecteur", "Actif",
        "Composant affecté", "Root Cause", "Description",
        "Chaîne d'exploitation", "Finding Evidence", "Impact",
        "Surface résiduelle", "Recommandation", "Action corrective",
        "Délai", "Références"
    ]
    # Construire les positions de chaque champ
    positions = []
    for field in fields:
        m = re.search(rf"^{re.escape(field)}:", content, re.MULTILINE)
        if m:
            positions.append((field, m.start(), m.end()))

    positions.sort(key=lambda x: x[1])

    for i, (field, start, end) in enumerate(positions):
        next_start = positions[i + 1][1] if i + 1 < len(positions) else len(content)
        value = content[end:next_start].strip()
        finding[field] = value

    return finding

def create_project(client_name: str, ref: str) -> str:
    payload = {
        "name": f"{client_name} - {ref}",
        "project_type": DESIGN_ID,
        "tags": ["SK Security"]
    }
    r = requests.post(
        f"{SYSREPTOR_URL}/api/v1/pentestprojects/",
        headers=sysreptor_headers(),
        json=payload
    )
    if not r.ok:
        print(f"[!] Erreur création projet : {r.status_code} - {r.text}")
        r.raise_for_status()
    project_id = r.json()["id"]
    print(f"[+] Projet créé : {project_id}")
    return project_id


def update_section(project_id: str, section_id: str, data: dict):
    """Injecter les données dans une section spécifique de SysReptor."""
    r = requests.patch(
        f"{SYSREPTOR_URL}/api/v1/pentestprojects/{project_id}/sections/{section_id}/",
        headers=sysreptor_headers(),
        json={"data": data}
    )
    if not r.ok:
        print(f"[!] Erreur section {section_id} : {r.status_code} - {r.text}")
    else:
        print(f"[+] Section '{section_id}' injectée")


def create_finding(project_id: str, finding_data: dict, finding_id: str):
    cvss_vector = finding_data.get("CVSS Vecteur", "n/a")

    # Références - une par ligne commençant par http
    refs_raw = finding_data.get("Références", "")
    refs = [r.strip() for r in refs_raw.splitlines() if r.strip().startswith("http")]

    payload = {
        "data": {
            "title":              finding_data.get("Titre", "TODO"),
            "cvss":               cvss_vector,
            "finding_id":         finding_id,
            "cwe_cve":            finding_data.get("CWE", "CWE-TODO"),
            "affected_asset":     finding_data.get("Actif", "TODO"),
            "affected_component": finding_data.get("Composant affecté", "TODO"),
            "root_cause":         finding_data.get("Root Cause", "TODO"),
            "description":        finding_data.get("Description", "TODO"),
            "exploitation_chain": finding_data.get("Chaîne d'exploitation", "TODO"),
            "finding_evidence":   finding_data.get("Finding Evidence", "TODO"),
            "impact":             finding_data.get("Impact", "TODO"),
            "residual_surface":   finding_data.get("Surface résiduelle", "TODO"),
            "recommendation":     finding_data.get("Recommandation", "TODO"),
            "references":         refs,
            "action_corrective":  finding_data.get("Action corrective", "TODO"),
            "delai_remediation":  finding_data.get("Délai", "2 semaines"),
        }
    }
    r = requests.post(
        f"{SYSREPTOR_URL}/api/v1/pentestprojects/{project_id}/findings/",
        headers=sysreptor_headers(),
        json=payload
    )
    if not r.ok:
        print(f"[!] Erreur création finding : {r.status_code} - {r.text}")
        r.raise_for_status()
    fid = r.json()["id"]
    print(f"[+] Finding créé : {finding_data.get('Titre', 'TODO')} ({fid})")
    return fid


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 sk_inject.py rapport_formate.txt")
        sys.exit(1)

    if not SYSREPTOR_TOKEN:
        print("Erreur : SYSREPTOR_TOKEN manquant.")
        print("Lance : export SYSREPTOR_TOKEN=ton_token")
        sys.exit(1)

    with open(sys.argv[1], "r", encoding="utf-8") as f:
        text = f.read()

    text = sanitize(text)

    print("[*] Parsing du fichier formaté...")
    blocks = parse_blocks(text)

    if not blocks:
        print("[!] Aucun bloc détecté. Vérifie que le fichier contient des blocs === NOM ===")
        sys.exit(1)

    # Infos générales
    info        = parse_info(blocks.get("INFORMATIONS GÉNÉRALES", ""))
    client_name = info.get("Nom du client", "Client")
    ref         = info.get("Référence", "REF-0001")
    audit_type  = info.get("Type d'audit", "Boîte grise")
    period      = info.get("Période", "TODO")
    access      = info.get("Accès fournis", "Compte de domaine (credentials fournis de manière sécurisée)")
    risk_level  = info.get("Niveau de risque global", "CRITIQUE").upper()

    print(f"[*] Client : {client_name} | Ref : {ref} | Risque : {risk_level}")

    # Création projet
    project_id = create_project(client_name, ref)

    # Injection par section selon la structure SysReptor
    update_section(project_id, "general", {
        "title":             f"{client_name} - {ref}",
        "client_name":       client_name,
        "ref":               ref,
        "version":           "1.0",
        "date":              date.today().isoformat(),
        "audit_type":        audit_type,
        "risk_level":        risk_level.capitalize(),
        "period":            period,
        "access":            access,
        "executive_summary": blocks.get("report.executive_summary", "TODO"),
    })
    update_section(project_id, "contacts", {
        "client_contacts": blocks.get("CONTACTS CLIENT", "TODO"),
    })
    update_section(project_id, "scope_section", {
        "scope":          blocks.get("report.scope", "TODO"),
        "scope_negative": blocks.get("report.scope_negative", "TODO"),
        "methodology":    blocks.get("report.methodology", "TODO"),
        "tools_used":     blocks.get("report.tools", "TODO"),
    })
    update_section(project_id, "content", {
    	"introduction":     blocks.get("report.introduction", "TODO"),
    	"findings_intro":   blocks.get("report.findings_intro", "Les scores CVSS présentés ci-après évaluent chaque vulnérabilité en isolation, indépendamment des autres maillons de la chaîne d'attaque."),
    	"timeline":         blocks.get("report.timeline", "TODO"),
    	"iocs":             blocks.get("report.iocs", "TODO"),
    	"remediation_plan": blocks.get("report.remediation_plan", "TODO"),
    	"residual_attack_surface": blocks.get("report.residual_attack_surface", "TODO"),
    	"conclusion":       blocks.get("report.conclusion", "TODO"),
    })
    # Findings
    finding_blocks = {k: v for k, v in blocks.items() if k.startswith("FINDING")}
    print(f"[*] {len(finding_blocks)} finding(s) détecté(s)...")

    for i, (fname, fcontent) in enumerate(finding_blocks.items(), 1):
        # Extraire l'ID depuis le nom du bloc (ex: "FINDING REF-0001")
        id_match = re.search(r"REF-\d+", fname)
        finding_id = id_match.group(0) if id_match else f"REF-{i:04d}"
        finding = parse_finding(fcontent)
        create_finding(project_id, finding, finding_id)

    print(f"\n[+] Rapport injecté avec succès !")
    print(f"[+] Ouvre SysReptor : {SYSREPTOR_URL}/projects/{project_id}/")


if __name__ == "__main__":
    main()
