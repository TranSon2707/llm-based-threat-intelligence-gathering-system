"""
enrichment/ner_spacy.py
========================
spaCy-based Named Entity Recognition (NER) for threat intelligence text.

What it extracts
-----------------
  THREAT_ACTOR   Persons / groups identified as attackers (spaCy PERSON label
                 + custom org patterns like APT groups)
  MALWARE        Known malware family names (via custom EntityRuler)

Custom patterns cover the most commonly reported malware families and APT
group aliases so the base en_core_web_sm model is boosted with domain
knowledge.  The pattern list is intentionally extensible — add new entries
to MALWARE_PATTERNS or APT_PATTERNS as needed.

All results are persisted to the ``entities`` table via db/queries.py.

Usage
-----
    from enrichment.ner_spacy import extract_and_store_ner

    extract_and_store_ner(source_id=42, cleaned_text="Lazarus Group deployed WannaCry...")
"""

from __future__ import annotations

import logging
from typing import NamedTuple

import spacy
from spacy.language import Language
from spacy.pipeline import EntityRuler

from db.sqlite_manager import insert_entity

logger = logging.getLogger(__name__)

# ── Custom pattern catalogue ──────────────────────────────────────────────────

# Malware family names (case-insensitive matching via lowercase patterns)
# Covers ransomware, banking trojans, RATs, backdoors, info-stealers, wipers, worms, APT tools, and more
MALWARE_PATTERNS: list[dict] = [
    # ── Ransomware ───────────────────────────────────────────────────────────
    {"label": "MALWARE", "pattern": "WannaCry"},
    {"label": "MALWARE", "pattern": "WannaCrypt"},
    {"label": "MALWARE", "pattern": "NotPetya"},
    {"label": "MALWARE", "pattern": "Petya"},
    {"label": "MALWARE", "pattern": "REvil"},
    {"label": "MALWARE", "pattern": "Ransomware-as-a-Service"},
    {"label": "MALWARE", "pattern": "LockBit"},
    {"label": "MALWARE", "pattern": "LockBit 2.0"},
    {"label": "MALWARE", "pattern": "LockBit 3.0"},
    {"label": "MALWARE", "pattern": "BlackCat"},
    {"label": "MALWARE", "pattern": "ALPHV"},
    {"label": "MALWARE", "pattern": "Noberus"},
    {"label": "MALWARE", "pattern": "Conti"},
    {"label": "MALWARE", "pattern": "Ryuk"},
    {"label": "MALWARE", "pattern": "DarkSide"},
    {"label": "MALWARE", "pattern": "Hive"},
    {"label": "MALWARE", "pattern": "BlackMatter"},
    {"label": "MALWARE", "pattern": "Clop"},
    {"label": "MALWARE", "pattern": "CL0P"},
    {"label": "MALWARE", "pattern": "Cuba"},
    {"label": "MALWARE", "pattern": "Cuba Ransomware"},
    {"label": "MALWARE", "pattern": "MedusaLocker"},
    {"label": "MALWARE", "pattern": "Egregor"},
    {"label": "MALWARE", "pattern": "Babuk"},
    {"label": "MALWARE", "pattern": "BabukLocker"},
    {"label": "MALWARE", "pattern": "AvosLocker"},
    {"label": "MALWARE", "pattern": "AvosLocker"},
    {"label": "MALWARE", "pattern": "PayOrMedia"},
    {"label": "MALWARE", "pattern": "Ragnar"},
    {"label": "MALWARE", "pattern": "Ragnar Locker"},
    {"label": "MALWARE", "pattern": "Haron"},
    {"label": "MALWARE", "pattern": "Nokoyawa"},
    {"label": "MALWARE", "pattern": "Nokoyawa Ransomware"},
    {"label": "MALWARE", "pattern": "AstraLocker"},
    {"label": "MALWARE", "pattern": "AstraLocker 2.0"},
    {"label": "MALWARE", "pattern": "Moonstone Sleet"},
    {"label": "MALWARE", "pattern": "Rainbow"},
    {"label": "MALWARE", "pattern": "Cactus"},
    {"label": "MALWARE", "pattern": "Cactus Ransomware"},
    {"label": "MALWARE", "pattern": "Abyss"},
    {"label": "MALWARE", "pattern": "Abyss Ransom"},
    {"label": "MALWARE", "pattern": "DragonFire"},
    {"label": "MALWARE", "pattern": "Money Message"},
    {"label": "MALWARE", "pattern": "MoneyMessage"},
    {"label": "MALWARE", "pattern": "BianLian"},
    {"label": "MALWARE", "pattern": "BianLian Ransomware"},
    {"label": "MALWARE", "pattern": "Akira"},
    {"label": "MALWARE", "pattern": "Akira Ransomware"},
    {"label": "MALWARE", "pattern": "3AM"},
    {"label": "MALWARE", "pattern": "3AM Ransomware"},
    {"label": "MALWARE", "pattern": "DarkVault"},
    {"label": "MALWARE", "pattern": "Inc Ransomware"},
    {"label": "MALWARE", "pattern": "INC Ransomware"},
    {"label": "MALWARE", "pattern": "Black Basta"},
    {"label": "MALWARE", "pattern": "BlackBasta"},
    {"label": "MALWARE", "pattern": "Volt Typhoon"},
    # ── Banking Trojans ──────────────────────────────────────────────────────
    {"label": "MALWARE", "pattern": "Emotet"},
    {"label": "MALWARE", "pattern": "TrickBot"},
    {"label": "MALWARE", "pattern": "Trickbot"},
    {"label": "MALWARE", "pattern": "Dridex"},
    {"label": "MALWARE", "pattern": "Ursnif"},
    {"label": "MALWARE", "pattern": "Ursnif"},
    {"label": "MALWARE", "pattern": "Gozi"},
    {"label": "MALWARE", "pattern": "Gozi ISFB"},
    {"label": "MALWARE", "pattern": "ISFB"},
    {"label": "MALWARE", "pattern": "Qakbot"},
    {"label": "MALWARE", "pattern": "QBot"},
    {"label": "MALWARE", "pattern": "Quakbot"},
    {"label": "MALWARE", "pattern": "IcedID"},
    {"label": "MALWARE", "pattern": "IcedID"},
    {"label": "MALWARE", "pattern": "BokBot"},
    {"label": "MALWARE", "pattern": "Bokbot"},
    {"label": "MALWARE", "pattern": "Grandoreiro"},
    {"label": "MALWARE", "pattern": "Mekotio"},
    {"label": "MALWARE", "pattern": "Ousaban"},
    {"label": "MALWARE", "pattern": "Casbaneiro"},
    {"label": "MALWARE", "pattern": "Guildma"},
    {"label": "MALWARE", "pattern": "Javalifter"},
    {"label": "MALWARE", "pattern": "Tetrade"},
    # ── RATs / Backdoors ──────────────────────────────────────────────────────
    {"label": "MALWARE", "pattern": "Cobalt Strike"},
    {"label": "MALWARE", "pattern": "CobaltStrike"},
    {"label": "MALWARE", "pattern": "Metasploit"},
    {"label": "MALWARE", "pattern": "AsyncRAT"},
    {"label": "MALWARE", "pattern": "AsyncRat"},
    {"label": "MALWARE", "pattern": "njRAT"},
    {"label": "MALWARE", "pattern": "Blot"},
    {"label": "MALWARE", "pattern": "NanoCore"},
    {"label": "MALWARE", "pattern": "NanoCore RAT"},
    {"label": "MALWARE", "pattern": "DarkComet"},
    {"label": "MALWARE", "pattern": "DarkComet RAT"},
    {"label": "MALWARE", "pattern": "Remcos"},
    {"label": "MALWARE", "pattern": "Remcos RAT"},
    {"label": "MALWARE", "pattern": "Agent Tesla"},
    {"label": "MALWARE", "pattern": "AgentTesla"},
    {"label": "MALWARE", "pattern": "Agent Tesla"},
    {"label": "MALWARE", "pattern": "AgenTesla"},
    {"label": "MALWARE", "pattern": "Loda"},
    {"label": "MALWARE", "pattern": "Loda RAT"},
    {"label": "MALWARE", "pattern": "Venom RAT"},
    {"label": "MALWARE", "pattern": "VenomRat"},
    {"label": "MALWARE", "pattern": "DCRat"},
    {"label": "MALWARE", "pattern": "DC RAT"},
    {"label": "MALWARE", "pattern": "DarkCrystal RAT"},
    {"label": "MALWARE", "pattern": "Quasar RAT"},
    {"label": "MALWARE", "pattern": "QuasarRAT"},
    {"label": "MALWARE", "pattern": "SeroXen RAT"},
    {"label": "MALWARE", "pattern": "SeroXenRAT"},
    {"label": "MALWARE", "pattern": "Warzone RAT"},
    {"label": "MALWARE", "pattern": "WarzoneRAT"},
    {"label": "MALWARE", "pattern": "Adwind"},
    {"label": "MALWARE", "pattern": "Adwind RAT"},
    {"label": "MALWARE", "pattern": "jRAT"},
    {"label": "MALWARE", "pattern": "JRAT"},
    {"label": "MALWARE", "pattern": "K_INS"},
    {"label": "MALWARE", "pattern": "Kinsing"},
    {"label": "MALWARE", "pattern": "Kinsing"},
    {"label": "MALWARE", "pattern": "Hildie"},
    {"label": "MALWARE", "pattern": "Hildie"},
    {"label": "MALWARE", "pattern": "Sapphire"},
    {"label": "MALWARE", "pattern": "Sapphire RAT"},
    {"label": "MALWARE", "pattern": "Pandora"},
    {"label": "MALWARE", "pattern": "Pandora RAT"},
    {"label": "MALWARE", "pattern": "Paradise"},
    {"label": "MALWARE", "pattern": "Paradise RAT"},
    {"label": "MALWARE", "pattern": "FUDCrypt"},
    {"label": "MALWARE", "pattern": "Parallax RAT"},
    # ── Info Stealers ─────────────────────────────────────────────────────────
    {"label": "MALWARE", "pattern": "Redline"},
    {"label": "MALWARE", "pattern": "RedLine"},
    {"label": "MALWARE", "pattern": "RedLine Stealer"},
    {"label": "MALWARE", "pattern": "RedLineStealer"},
    {"label": "MALWARE", "pattern": "Raccoon"},
    {"label": "MALWARE", "pattern": "Raccoon Stealer"},
    {"label": "MALWARE", "pattern": "Raccoon Stealer"},
    {"label": "MALWARE", "pattern": "Vidar"},
    {"label": "MALWARE", "pattern": "Vidar Stealer"},
    {"label": "MALWARE", "pattern": "Taurus"},
    {"label": "MALWARE", "pattern": "Taurus Stealer"},
    {"label": "MALWARE", "pattern": "Aurora"},
    {"label": "MALWARE", "pattern": "Aurora Stealer"},
    {"label": "MALWARE", "pattern": "Lumma"},
    {"label": "MALWARE", "pattern": "LummaC2"},
    {"label": "MALWARE", "pattern": "Lumma Stealer"},
    {"label": "MALWARE", "pattern": "StealC"},
    {"label": "MALWARE", "pattern": "StealC Stealer"},
    {"label": "MALWARE", "pattern": "Atomic Stealer"},
    {"label": "MALWARE", "pattern": "AtomicMacStealer"},
    {"label": "MALWARE", "pattern": "MetaStealer"},
    {"label": "MALWARE", "pattern": "Meta Stealer"},
    {"label": "MALWARE", "pattern": "Cleo"},
    {"label": "MALWARE", "pattern": "Cleo RAT"},
    {"label": "MALWARE", "pattern": "Clipper"},
    {"label": "MALWARE", "pattern": "CryptClipper"},
    {"label": "MALWARE", "pattern": "SolarMarker"},
    {"label": "MALWARE", "pattern": "Jupyter"},
    {"label": "MALWARE", "pattern": "Jupyter Info Stealer"},
    {"label": "MALWARE", "pattern": "Rhadamanthys"},
    {"label": "MALWARE", "pattern": "Rhadamanthys Stealer"},
    {"label": "MALWARE", "pattern": "Private Loader"},
    {"label": "MALWARE", "pattern": "PrivateLoader"},
    {"label": "MALWARE", "pattern": "Vidar"},
    # ── APT / Espionage Tools ──────────────────────────────────────────────────
    {"label": "MALWARE", "pattern": "EternalBlue"},
    {"label": "MALWARE", "pattern": "EternalRomance"},
    {"label": "MALWARE", "pattern": "EternalChampion"},
    {"label": "MALWARE", "pattern": "DoublePulsar"},
    {"label": "MALWARE", "pattern": "BlueKeep"},
    {"label": "MALWARE", "pattern": "BlueKeep"},
    {"label": "MALWARE", "pattern": "Log4Shell"},
    {"label": "MALWARE", "pattern": "Log4j"},
    {"label": "MALWARE", "pattern": "Log4j2"},
    {"label": "MALWARE", "pattern": "CVE-2021-44228"},
    {"label": "MALWARE", "pattern": "Mirai"},
    {"label": "MALWARE", "pattern": "Mirai Botnet"},
    {"label": "MALWARE", "pattern": "Moobot"},
    {"label": "MALWARE", "pattern": "Mozi"},
    {"label": "MALWARE", "pattern": "Mozi Botnet"},
    {"label": "MALWARE", "pattern": "Sality"},
    {"label": "MALWARE", "pattern": "Sliver"},
    {"label": "MALWARE", "pattern": "Sliver Framework"},
    {"label": "MALWARE", "pattern": "Havoc"},
    {"label": "MALWARE", "pattern": "Havoc Framework"},
    {"label": "MALWARE", "pattern": "Brute Ratel"},
    {"label": "MALWARE", "pattern": "BruteRatel"},
    {"label": "MALWARE", "pattern": "Brute Ratel C4"},
    {"label": "MALWARE", "pattern": "Mimic"},
    {"label": "MALWARE", "pattern": "Mimic RAT"},
    {"label": "MALWARE", "pattern": "Mimic Ransomware"},
    {"label": "MALWARE", "pattern": "Nightmare"},
    {"label": "MALWARE", "pattern": "Nightmare Ransomware"},
    {"label": "MALWARE", "pattern": "PlugX"},
    {"label": "MALWARE", "pattern": "PlugX"},
    {"label": "MALWARE", "pattern": "Korplug"},
    {"label": "MALWARE", "pattern": "Korplug RAT"},
    {"label": "MALWARE", "pattern": "Gh0st"},
    {"label": "MALWARE", "pattern": "Gh0st RAT"},
    {"label": "MALWARE", "pattern": "Gh0stRAT"},
    {"label": "MALWARE", "pattern": "Gh0stC"},
    {"label": "MALWARE", "pattern": "K Pot"},
    {"label": "MALWARE", "pattern": "Kpot"},
    {"label": "MALWARE", "pattern": "Kpot Stealer"},
    {"label": "MALWARE", "pattern": "Red Alert"},
    {"label": "MALWARE", "pattern": "RedAlert Ransomware"},
    {"label": "MALWARE", "pattern": "Sabbath"},
    {"label": "MALWARE", "pattern": "Sabbath Ransomware"},
    {"label": "MALWARE", "pattern": "Magniber"},
    {"label": "MALWARE", "pattern": "Magniber Ransomware"},
    {"label": "MALWARE", "pattern": "PYSA"},
    {"label": "MALWARE", "pattern": "PYSA Ransomware"},
    {"label": "MALWARE", "pattern": "Mespinoza"},
    {"label": "MALWARE", "pattern": "Mespinoza Ransomware"},
    {"label": "MALWARE", "pattern": "Prometei"},
    {"label": "MALWARE", "pattern": "Prometei Botnet"},
    {"label": "MALWARE", "pattern": "Ficker"},
    {"label": "MALWARE", "pattern": "Ficker Stealer"},
    {"label": "MALWARE", "pattern": "RedLine"},
    {"label": "MALWARE", "pattern": "RedLine Stealer"},
    {"label": "MALWARE", "pattern": "Vidar"},
    {"label": "MALWARE", "pattern": "Vidar Stealer"},
    {"label": "MALWARE", "pattern": "Predator"},
    {"label": "MALWARE", "pattern": "Predator Spyware"},
    {"label": "MALWARE", "pattern": "Pegasus"},
    {"label": "MALWARE", "pattern": "Pegasus Spyware"},
    {"label": "MALWARE", "pattern": "FinFisher"},
    {"label": "MALWARE", "pattern": "FinFisher Spyware"},
    {"label": "MALWARE", "pattern": "FinFisher"},
    {"label": "MALWARE", "pattern": "Cytrox"},
    {"label": "MALWARE", "pattern": "Cytrox Predator"},
    {"label": "MALWARE", "pattern": "SocGholish"},
    {"label": "MALWARE", "pattern": "FakeUpdates"},
    {"label": "MALWARE", "pattern": "GootLoader"},
    {"label": "MALWARE", "pattern": "IcedID"},
    {"label": "MALWARE", "pattern": "IcedID Loader"},
    {"label": "MALWARE", "pattern": "Buer Loader"},
    {"label": "MALWARE", "pattern": "Buer"},
    {"label": "MALWARE", "pattern": "Buer Malware"},
    {"label": "MALWARE", "pattern": "UAT564"},
    {"label": "MALWARE", "pattern": "Emphant"},
    {"label": "MALWARE", "pattern": "Emphant Botnet"},
    {"label": "MALWARE", "pattern": "SysJoker"},
    {"label": "MALWARE", "pattern": "TrueBot"},
    {"label": "MALWARE", "pattern": "TrueBot"},
    {"label": "MALWARE", "pattern": "True Bot"},
    {"label": "MALWARE", "pattern": "FunkSec"},
    {"label": "MALWARE", "pattern": "FunkSec Ransomware"},
    {"label": "MALWARE", "pattern": "Hunters International"},
    {"label": "MALWARE", "pattern": "HuntersInternational"},
    {"label": "MALWARE", "pattern": "Cactus"},
    {"label": "MALWARE", "pattern": "Cactus Ransomware"},
    {"label": "MALWARE", "pattern": "Dagon"},
    {"label": "MALWARE", "pattern": "Dagon Locker"},
    {"label": "MALWARE", "pattern": "ElDORADO"},
    {"label": "MALWARE", "pattern": "ElDorado Ransomware"},
    {"label": "MALWARE", "pattern": "MadLiberator"},
    {"label": "MALWARE", "pattern": "Mac Liberator"},
    {"label": "MALWARE", "pattern": "ShadowVault"},
    {"label": "MALWARE", "pattern": "ShadowVault Mac Stealer"},
    {"label": "MALWARE", "pattern": "Rusty"},
    {"label": "MALWARE", "pattern": "Rusty Attribute"},
    {"label": "MALWARE", "pattern": "MacMa"},
    {"label": "MALWARE", "pattern": "MacMa macOS Backdoor"},
    {"label": "MALWARE", "pattern": "Bansh22"},
    {"label": "MALWARE", "pattern": "Banshee"},
    {"label": "MALWARE", "pattern": "Banshee Stealer"},
    {"label": "MALWARE", "pattern": "Cocate"},
    {"label": "MALWARE", "pattern": "SwiftSweeper"},
    {"label": "MALWARE", "pattern": "CloudMensis"},
    {"label": "MALWARE", "pattern": "CloudMensis macOS"},
    {"label": "MALWARE", "pattern": "Cymmor"},
    {"label": "MALWARE", "pattern": "LightSpy"},
    {"label": "MALWARE", "pattern": "LightSpy iOS Spyware"},
    {"label": "MALWARE", "pattern": "TwoFace"},
    {"label": "MALWARE", "pattern": "TwoFace Webshell"},
    {"label": "MALWARE", "pattern": "Pillow"},
    {"label": "MALWARE", "pattern": "Pillow Salt Encryption"},
    {"label": "MALWARE", "pattern": "KeySnail"},
    {"label": "MALWARE", "pattern": "KeySnail Firefox Extension"},
    {"label": "MALWARE", "pattern": "ZeuS"},
    {"label": "MALWARE", "pattern": "Zeus"},
    {"label": "MALWARE", "pattern": "SpyEye"},
    {"label": "MALWARE", "pattern": "Carberp"},
    {"label": "MALWARE", "pattern": "Carbanak"},
    {"label": "MALWARE", "pattern": "Anunak"},
    {"label": "MALWARE", "pattern": "DanaBot"},
    {"label": "MALWARE", "pattern": "SystemBC"},
    {"label": "MALWARE", "pattern": "Zloader"},
    {"label": "MALWARE", "pattern": "ZLoader"},
    {"label": "MALWARE", "pattern": "Bumblebee"},
    {"label": "MALWARE", "pattern": "BumbleBee"},
]

# APT group / threat-actor aliases that spaCy's PERSON label often misses
# Includes Russian, Chinese, Iranian, North Korean, and other major state-sponsored and criminal groups
APT_PATTERNS: list[dict] = [
    # ── Russia ──────────────────────────────────────────────────────────────
    {"label": "THREAT_ACTOR", "pattern": "APT28"},
    {"label": "THREAT_ACTOR", "pattern": "Fancy Bear"},
    {"label": "THREAT_ACTOR", "pattern": "Pawn Storm"},
    {"label": "THREAT_ACTOR", "pattern": "Sofacy"},
    {"label": "THREAT_ACTOR", "pattern": "Sednit"},
    {"label": "THREAT_ACTOR", "pattern": "Strontium"},
    {"label": "THREAT_ACTOR", "pattern": "APT29"},
    {"label": "THREAT_ACTOR", "pattern": "Cozy Bear"},
    {"label": "THREAT_ACTOR", "pattern": "The Dukes"},
    {"label": "THREAT_ACTOR", "pattern": "Nobelium"},
    {"label": "THREAT_ACTOR", "pattern": "YTTRIUM"},
    {"label": "THREAT_ACTOR", "pattern": "UNC2452"},
    {"label": "THREAT_ACTOR", "pattern": "Sandworm"},
    {"label": "THREAT_ACTOR", "pattern": "Voodoo Bear"},
    {"label": "THREAT_ACTOR", "pattern": "TeleBots"},
    {"label": "THREAT_ACTOR", "pattern": "BlackEnergy"},
    {"label": "THREAT_ACTOR", "pattern": "Turla"},
    {"label": "THREAT_ACTOR", "pattern": "Venomous Bear"},
    {"label": "THREAT_ACTOR", "pattern": "Snake Group"},
    {"label": "THREAT_ACTOR", "pattern": "Uroburos"},
    {"label": "THREAT_ACTOR", "pattern": "Waterbug"},
    {"label": "THREAT_ACTOR", "pattern": "Gamaredon"},
    {"label": "THREAT_ACTOR", "pattern": "Armageddon"},
    {"label": "THREAT_ACTOR", "pattern": "Shuckworm"},
    {"label": "THREAT_ACTOR", "pattern": "Primitive Bear"},
    {"label": "THREAT_ACTOR", "pattern": "Dragonfly"},
    {"label": "THREAT_ACTOR", "pattern": "Energetic Bear"},
    {"label": "THREAT_ACTOR", "pattern": "Crouching Yeti"},
    # ── China ───────────────────────────────────────────────────────────────
    {"label": "THREAT_ACTOR", "pattern": "APT1"},
    {"label": "THREAT_ACTOR", "pattern": "Comment Crew"},
    {"label": "THREAT_ACTOR", "pattern": "APT3"},
    {"label": "THREAT_ACTOR", "pattern": "Gothic Panda"},
    {"label": "THREAT_ACTOR", "pattern": "APT10"},
    {"label": "THREAT_ACTOR", "pattern": "Stone Panda"},
    {"label": "THREAT_ACTOR", "pattern": "MenuPass"},
    {"label": "THREAT_ACTOR", "pattern": "Cicada"},
    {"label": "THREAT_ACTOR", "pattern": "APT17"},
    {"label": "THREAT_ACTOR", "pattern": "Deputy Dog"},
    {"label": "THREAT_ACTOR", "pattern": "APT27"},
    {"label": "THREAT_ACTOR", "pattern": "Emissary Panda"},
    {"label": "THREAT_ACTOR", "pattern": "Iron Tiger"},
    {"label": "THREAT_ACTOR", "pattern": "APT31"},
    {"label": "THREAT_ACTOR", "pattern": "Zirconium"},
    {"label": "THREAT_ACTOR", "pattern": "APT41"},
    {"label": "THREAT_ACTOR", "pattern": "Double Dragon"},
    {"label": "THREAT_ACTOR", "pattern": "Winnti"},
    {"label": "THREAT_ACTOR", "pattern": "BARIUM"},
    {"label": "THREAT_ACTOR", "pattern": "Wicked Panda"},
    {"label": "THREAT_ACTOR", "pattern": "BlackTech"},
    {"label": "THREAT_ACTOR", "pattern": "APT15"},
    {"label": "THREAT_ACTOR", "pattern": "Kelebek"},
    {"label": "THREAT_ACTOR", "pattern": "Nickel"},
    {"label": "THREAT_ACTOR", "pattern": "Mustang Panda"},
    {"label": "THREAT_ACTOR", "pattern": "Bronze President"},
    {"label": "THREAT_ACTOR", "pattern": "RedDelta"},
    {"label": "THREAT_ACTOR", "pattern": "APT30"},
    {"label": "THREAT_ACTOR", "pattern": "APT32"},
    {"label": "THREAT_ACTOR", "pattern": "OceanLotus"},
    {"label": "THREAT_ACTOR", "pattern": "Hafnium"},
    {"label": "THREAT_ACTOR", "pattern": "Volt Typhoon"},
    {"label": "THREAT_ACTOR", "pattern": "Vanguard Panda"},
    {"label": "THREAT_ACTOR", "pattern": "BRONZE SILHOUETTE"},
    {"label": "THREAT_ACTOR", "pattern": "Silk Typhoon"},
    {"label": "THREAT_ACTOR", "pattern": "Brass Typhoon"},
    {"label": "THREAT_ACTOR", "pattern": "Charcoal Typhoon"},
    # ── Iran ────────────────────────────────────────────────────────────────
    {"label": "THREAT_ACTOR", "pattern": "APT33"},
    {"label": "THREAT_ACTOR", "pattern": "Elfin"},
    {"label": "THREAT_ACTOR", "pattern": "Refined Kitten"},
    {"label": "THREAT_ACTOR", "pattern": "APT34"},
    {"label": "THREAT_ACTOR", "pattern": "OilRig"},
    {"label": "THREAT_ACTOR", "pattern": "Helix Kitten"},
    {"label": "THREAT_ACTOR", "pattern": "APT35"},
    {"label": "THREAT_ACTOR", "pattern": "Charming Kitten"},
    {"label": "THREAT_ACTOR", "pattern": "Newscaster"},
    {"label": "THREAT_ACTOR", "pattern": "Phosphorus"},
    {"label": "THREAT_ACTOR", "pattern": "APT39"},
    {"label": "THREAT_ACTOR", "pattern": "Chafer"},
    {"label": "THREAT_ACTOR", "pattern": "Remix Kitten"},
    {"label": "THREAT_ACTOR", "pattern": "MuddyWater"},
    {"label": "THREAT_ACTOR", "pattern": "Static Kitten"},
    {"label": "THREAT_ACTOR", "pattern": "Mercury"},
    {"label": "THREAT_ACTOR", "pattern": "Mango Sandstorm"},
    {"label": "THREAT_ACTOR", "pattern": "Mint Sandstorm"},
    {"label": "THREAT_ACTOR", "pattern": "Peach Sandstorm"},
    {"label": "THREAT_ACTOR", "pattern": "Hazel Sandstorm"},
    # ── North Korea ─────────────────────────────────────────────────────────
    {"label": "THREAT_ACTOR", "pattern": "Lazarus Group"},
    {"label": "THREAT_ACTOR", "pattern": "Lazarus"},
    {"label": "THREAT_ACTOR", "pattern": "Hidden Cobra"},
    {"label": "THREAT_ACTOR", "pattern": "Zinc"},
    {"label": "THREAT_ACTOR", "pattern": "ApplePencil"},
    {"label": "THREAT_ACTOR", "pattern": "APT37"},
    {"label": "THREAT_ACTOR", "pattern": "Reaper"},
    {"label": "THREAT_ACTOR", "pattern": "Ricochet Chollima"},
    {"label": "THREAT_ACTOR", "pattern": "Scarcruft"},
    {"label": "THREAT_ACTOR", "pattern": "APT38"},
    {"label": "THREAT_ACTOR", "pattern": "BlueNoroff"},
    {"label": "THREAT_ACTOR", "pattern": "Kimsuky"},
    {"label": "THREAT_ACTOR", "pattern": "Velvet Chollima"},
    {"label": "THREAT_ACTOR", "pattern": "Black Banshee"},
    {"label": "THREAT_ACTOR", "pattern": "Emerald Sleet"},
    {"label": "THREAT_ACTOR", "pattern": "Onyx Sleet"},
    {"label": "THREAT_ACTOR", "pattern": "Diamond Sleet"},
    {"label": "THREAT_ACTOR", "pattern": "Ruby Sleet"},
    {"label": "THREAT_ACTOR", "pattern": "Jade Sleet"},
    {"label": "THREAT_ACTOR", "pattern": "Sapphire Sleet"},
    # ── Criminal / Other ─────────────────────────────────────────────────────
    {"label": "THREAT_ACTOR", "pattern": "FIN1"},
    {"label": "THREAT_ACTOR", "pattern": "FIN4"},
    {"label": "THREAT_ACTOR", "pattern": "FIN5"},
    {"label": "THREAT_ACTOR", "pattern": "FIN6"},
    {"label": "THREAT_ACTOR", "pattern": "FIN7"},
    {"label": "THREAT_ACTOR", "pattern": "FIN8"},
    {"label": "THREAT_ACTOR", "pattern": "FIN10"},
    {"label": "THREAT_ACTOR", "pattern": "FIN11"},
    {"label": "THREAT_ACTOR", "pattern": "FIN12"},
    {"label": "THREAT_ACTOR", "pattern": "FIN13"},
    {"label": "THREAT_ACTOR", "pattern": "UNC2452"},
    {"label": "THREAT_ACTOR", "pattern": "LAPSUS$"},
    {"label": "THREAT_ACTOR", "pattern": [{"LOWER": "lapsus"}, {"TEXT": "$"}]},
    {"label": "THREAT_ACTOR", "pattern": "Scattered Spider"},
    {"label": "THREAT_ACTOR", "pattern": "Octo Tempest"},
    {"label": "THREAT_ACTOR", "pattern": "UNC3944"},
    {"label": "THREAT_ACTOR", "pattern": "BlackBasta"},
    {"label": "THREAT_ACTOR", "pattern": "Black Basta"},
    {"label": "THREAT_ACTOR", "pattern": "Evil Corp"},
    {"label": "THREAT_ACTOR", "pattern": "Indrik Spider"},
    {"label": "THREAT_ACTOR", "pattern": "Magecart"},
    {"label": "THREAT_ACTOR", "pattern": "Wizard Spider"},
    {"label": "THREAT_ACTOR", "pattern": "Prophet Spider"},
    {"label": "THREAT_ACTOR", "pattern": "Storm-0558"},
    {"label": "THREAT_ACTOR", "pattern": "Storm-0216"},
    {"label": "THREAT_ACTOR", "pattern": "Storm-0501"},
    {"label": "THREAT_ACTOR", "pattern": "Vanilla Tempest"},
    {"label": "THREAT_ACTOR", "pattern": "Equation Group"},
    {"label": "THREAT_ACTOR", "pattern": "DarkHalo"},
    {"label": "THREAT_ACTOR", "pattern": "SolarWinds Attackers"},
    {"label": "THREAT_ACTOR", "pattern": "Hafnium"},
    {"label": "THREAT_ACTOR", "pattern": "TA505"},
    {"label": "THREAT_ACTOR", "pattern": "TA542"},
    {"label": "THREAT_ACTOR", "pattern": "TA402"},
    {"label": "THREAT_ACTOR", "pattern": "TA428"},
    {"label": "THREAT_ACTOR", "pattern": "TA416"}
]

# ── Model singleton ───────────────────────────────────────────────────────────

_NLP: Language | None = None


def _get_nlp() -> Language:
    """
    Load en_core_web_sm once and inject the custom EntityRuler before the
    built-in NER component so custom patterns take precedence.
    """
    global _NLP
    if _NLP is not None:
        return _NLP

    logger.info("[ner_spacy] Loading spaCy model en_core_web_sm …")
    nlp = spacy.load("en_core_web_sm")

    # EntityRuler added *before* ner so it can set spans that ner won't override
    ruler: EntityRuler = nlp.add_pipe(
        "entity_ruler",
        before="ner",
        config={"overwrite_ents": True},
    )
    ruler.add_patterns(MALWARE_PATTERNS + APT_PATTERNS)

    _NLP = nlp
    logger.info("[ner_spacy] Model ready with %d custom patterns.",
                len(MALWARE_PATTERNS) + len(APT_PATTERNS))
    return _NLP


# ── Public interface ───────────────────────────────────────────────────────────

class NEREntity(NamedTuple):
    entity_type:  str   # "THREAT_ACTOR" or "MALWARE"
    entity_value: str


def extract_ner_entities(text: str) -> list[NEREntity]:
    """
    Run NER over *text* and return deduplicated THREAT_ACTOR and MALWARE
    entities.

    Mapping from spaCy labels:
        PERSON  → THREAT_ACTOR  (individuals named in threat reports)
        MALWARE → MALWARE       (set by custom EntityRuler)
        THREAT_ACTOR → THREAT_ACTOR (set by custom EntityRuler for APT groups)

    GPE / ORG labels are intentionally excluded to reduce false positives
    (country names and vendor names are not threat actors).
    """
    if not text or not isinstance(text, str):
        return []

    nlp  = _get_nlp()
    # spaCy processes up to max_length chars; split long documents to be safe
    doc  = nlp(text[:100_000])

    seen:    set[tuple[str, str]] = set()
    results: list[NEREntity]      = []

    # List of common words in PERSON entities that are unlikely to be actual threat actors
    SAFE_TITLES = {
        "researcher", "analyst", "expert", "author", "director", "ceo", "reporter",
        "dr", "mr", "mrs", "ms", "professor", "spokesperson", "engineer", "victim",
        "user", "customer", "client", "investigator", "official", "representative",
        "agent", "developer", "founder", "executive", "president", "minister"
    }

    for ent in doc.ents:
        raw_label = ent.label_
        raw_value = ent.text.strip()

        if not raw_value:
            continue

        if raw_label == "PERSON":
            # Check the 3 tokens before the entity, stripping punctuation, to catch
            # "Dr. Jane", "Senior Researcher John", etc.
            preceding = [
                doc[i].text.lower().strip(".")
                for i in range(max(0, ent.start - 3), ent.start)
            ]
            if any(tok in SAFE_TITLES for tok in preceding):
                continue  # skip this PERSON entity as it's likely a safe title, not a threat actor
            
            etype = "THREAT_ACTOR"
        elif raw_label == "MALWARE":
            etype = "MALWARE"
        elif raw_label == "THREAT_ACTOR":
            etype = "THREAT_ACTOR"
        else:
            continue  # ignore GPE, ORG, DATE, etc.

        key = (etype, raw_value.lower())
        if key not in seen:
            seen.add(key)
            results.append(NEREntity(entity_type=etype, entity_value=raw_value))
 
    return results


def extract_and_store_ner(source_id: int, cleaned_text: str) -> list[NEREntity]:
    """
    Extract THREAT_ACTOR and MALWARE entities from *cleaned_text* and
    persist them to the ``entities`` table linked to *source_id*.

    Returns the list of extracted entities for testing / logging.
    """
    entities = extract_ner_entities(cleaned_text)

    for entity in entities:
        try:
            insert_entity(
                source_id=source_id,
                entity_type=entity.entity_type,
                entity_value=entity.entity_value,
            )
        except Exception as exc:
            logger.warning(
                "Failed to insert NER entity (%s=%s) for source_id=%d: %s",
                entity.entity_type, entity.entity_value, source_id, exc,
            )

    logger.info(
        "[ner_spacy] source_id=%d → %d NER entities extracted",
        source_id, len(entities),
    )
    return entities

