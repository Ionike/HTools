#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FANZA/SteamDB Game Folder Renamer
Multi-stage LLM workflow for accurate game identification and renaming
Supports searching on FANZA and/or SteamDB with Selenium browser automation
Format: [YYMMDD][ProductID][Author]Game Name
"""

import os
import json
import re
import sys
import time
import subprocess
import webbrowser
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import argparse

# Force UTF-8 encoding for console output to handle Japanese characters
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

logger = logging.getLogger(__name__)

try:
    import requests
    from urllib.parse import quote
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from webdriver_manager.chrome import ChromeDriverManager
    try:
        from selenium_stealth import stealth
        STEALTH_AVAILABLE = True
    except ImportError:
        STEALTH_AVAILABLE = False
        logger.warning("selenium_stealth not available, browser may be detected as bot")
except ImportError as e:
    logger.error(f"Required packages not installed. Install with: pip install requests selenium webdriver-manager selenium-stealth")
    logger.error(f"Import error: {e}")
    sys.exit(1)


class SearchPlatform(Enum):
    """Available search platforms"""
    FANZA = "fanza"
    STEAMDB = "steamdb"


class VerificationSource(Enum):
    """Sources used for game verification"""
    REGEX_FOLDER_NAME = "regex_folder_name"
    LLM_FILE_ANALYSIS = "llm_file_analysis"
    FANZA_SEARCH = "fanza_search"
    STEAMDB_SEARCH = "steamdb_search"
    DUCKDUCKGO_SEARCH = "duckduckgo_search"


@dataclass
class VerificationResult:
    """Result from multi-stage verification process"""
    is_found: bool
    platform: Optional[str] = None  # 'fanza', 'steamdb', or None
    confidence: str = 'low'  # 'high', 'medium', 'low'
    product_id: Optional[str] = None
    game_name: Optional[str] = None
    author: Optional[str] = None
    sources: List[VerificationSource] = field(default_factory=list)
    reasoning: str = ""
    url: Optional[str] = None


class LMStudioClient:
    """Client for LMStudio local LLM"""

    def __init__(self, host: str = "localhost", port: int = 1234):
        self.base_url = f"http://{host}:{port}"
        self.api_url = f"{self.base_url}/v1/chat/completions"

    def check_connection(self) -> bool:
        """Check if LMStudio is running"""
        try:
            response = requests.get(f"{self.base_url}/v1/models", timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Cannot connect to LMStudio: {e}")
            return False

    def query(self, prompt: str, temperature: float = 0.3, max_tokens: int = 2048) -> Optional[str]:
        """Query the LLM with a prompt"""
        try:
            payload = {
                "model": "local-model",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "max_tokens": max_tokens
            }

            logger.debug(f"LLM request: max_tokens={max_tokens}, temperature={temperature}")
            start_time = time.time()
            response = requests.post(self.api_url, json=payload, timeout=300)
            elapsed = time.time() - start_time
            logger.info(f"LLM response received in {elapsed:.1f}s")
            response.raise_for_status()

            result = response.json()
            if 'choices' in result and len(result['choices']) > 0:
                return result['choices'][0]['message']['content'].strip()
            return None
        except Exception as e:
            logger.error(f"LLM query failed: {e}")
            return None


class FolderAnalyzer:
    """Analyzes folder contents to find game-related files"""

    def __init__(self, llm: LMStudioClient):
        self.llm = llm

    def get_folder_contents(self, folder_path: str) -> Dict:
        """Get all files in folder with categorization"""
        contents = {
            'all_files': [],
            'executables': [],
            'text_files': [],
            'readme_files': [],
            'product_related': []
        }

        try:
            for root, dirs, files in os.walk(folder_path):
                depth = root.replace(folder_path, '').count(os.sep)
                if depth > 3:
                    continue

                for file in files:
                    file_lower = file.lower()
                    rel_path = os.path.relpath(os.path.join(root, file), folder_path)

                    contents['all_files'].append(rel_path)

                    if file_lower.endswith(('.exe', '.bat', '.cmd')):
                        contents['executables'].append(rel_path)

                    if file_lower.endswith(('.txt', '.md', '.readme')):
                        contents['text_files'].append(rel_path)

                    if any(x in file_lower for x in ['readme', 'お読み', '説明', 'manual', '読んで']):
                        contents['readme_files'].append(rel_path)
                    elif file_lower.endswith('.txt') and 'info' in file_lower:
                        contents['readme_files'].append(rel_path)

                    # FANZA/Steam related files
                    if any(x in file_lower for x in ['fanza', 'dmm', 'steam', 'appid']):
                        contents['product_related'].append(rel_path)

        except Exception as e:
            logger.error(f"Error reading folder {folder_path}: {e}")

        return contents

    def identify_useful_files(self, folder_name: str, contents: Dict) -> Dict:
        """Stage 1: LLM identifies which files contain useful game information"""

        if len(contents['all_files']) <= 3:
            useful = contents['text_files'] + contents['readme_files'] + contents['executables'][:1]
            if useful:
                logger.info(f"Few files detected, using all available: {useful}")
                return {
                    "useful_files": useful,
                    "reason": "Limited files available, using all"
                }

        if not contents['readme_files'] and not contents['text_files']:
            logger.info("No readme or text files found - will rely on search verification")
            return {
                "useful_files": contents['executables'][:1] if contents['executables'] else [],
                "reason": "No text files available, minimal local information"
            }

        prompt = f"""Select files with game title/author/product ID info.

Folder: {folder_name}
Executables: {', '.join(contents['executables'][:5]) if contents['executables'] else 'None'}
Text files: {', '.join(contents['text_files'][:8]) if contents['text_files'] else 'None'}
Product-related: {', '.join(contents['product_related'][:3]) if contents['product_related'] else 'None'}

Priority: readme.txt > product files > text files
DO NOT select .exe files (binary).

OUTPUT JSON ONLY:
{{"useful_files": ["readme.txt"], "reason": "brief"}}"""

        logger.info("="*60)
        logger.info("STAGE 1: LLM IDENTIFYING USEFUL FILES")
        logger.info("="*60)

        response = self.llm.query(prompt, temperature=0.3, max_tokens=2048)

        if response:
            try:
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group())
                    logger.info(f"PARSED JSON: {result}")
                    return result
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse LLM response")

        # Fallback
        useful_files = contents['readme_files'] + contents['product_related'] + contents['text_files']
        seen = set()
        useful_files = [f for f in useful_files if not (f in seen or seen.add(f))]

        return {
            "useful_files": useful_files[:5],
            "reason": "Fallback selection"
        }

    def read_file_content(self, folder_path: str, file_path: str, max_chars: int = 1000) -> str:
        """Read content from a text file with automatic encoding detection"""
        try:
            full_path = os.path.join(folder_path, file_path)
            encodings = ['utf-8', 'shift-jis', 'cp932', 'euc-jp', 'iso-2022-jp']

            for encoding in encodings:
                try:
                    with open(full_path, 'r', encoding=encoding) as f:
                        content = f.read(max_chars)
                        if content:
                            return content
                except (UnicodeDecodeError, UnicodeError):
                    continue

            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read(max_chars)

        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            return ""


class GameIdentifier:
    """Identifies game information using LLM"""

    def __init__(self, llm: LMStudioClient):
        self.llm = llm

    def identify_game(self, folder_name: str, useful_files: List[str],
                     file_contents: Dict[str, str]) -> Optional[Dict]:
        """Stage 2: LLM identifies game from folder name and file contents"""

        # Pre-extract Japanese title from readme files
        japanese_title_from_readme = None

        for filename, content in file_contents.items():
            if any(keyword in filename.lower() for keyword in ['readme', 'read me', '__readme', '読んで']):
                matches = re.findall(r'[『「]([^』」]+)[』」]', content)
                for title_text in matches:
                    title_text = title_text.strip()
                    japanese_match = re.search(r'([ぁ-んァ-ヶー一-龯]{2,}[ぁ-んァ-ヶー一-龯\s・～〜\-]*)', title_text)
                    if japanese_match and len(japanese_match.group(1).strip()) >= 3:
                        japanese_title_from_readme = japanese_match.group(1).strip()
                        logger.info(f"Pre-extracted Japanese title: '{japanese_title_from_readme}'")
                        break
                if japanese_title_from_readme:
                    break

        # Build context
        context = f"Folder name: {folder_name}\n\n"

        for file, content in file_contents.items():
            if file.lower().endswith(('.exe', '.dll', '.pak')):
                continue
            if content:
                if 'This program cannot be run in DOS mode' in content:
                    continue
                context += f"=== {file} ===\n{content[:600]}\n\n"

        prompt = f"""Extract game info from this game folder. Output JSON only.

{context}

RULES:
1. game_name = core title only (no dates, versions, language tags)
2. product_id = any product code found (FANZA format like d_xxxxx, Steam AppID, etc.)
3. author = circle/サークル/developer name, or null
4. platform = 'fanza', 'steam', 'dlsite', or 'unknown'

OUTPUT FORMAT (JSON only, no explanation):
{{"is_game": true, "game_name": "title", "product_id": "d_123456", "author": "circle", "platform": "fanza"}}"""

        logger.info("="*60)
        logger.info("STAGE 2: LLM EXTRACTING GAME INFO")
        logger.info("="*60)

        response = self.llm.query(prompt, temperature=0.3, max_tokens=2048)

        result = None
        if response:
            try:
                json_match = re.search(r'\{[^}]*"is_game"[^}]*\}', response, re.DOTALL)
                if not json_match:
                    json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group())
                    logger.info(f"LLM identified: {result}")

                    # Enhance with pre-extracted Japanese title
                    if japanese_title_from_readme:
                        llm_game_name = result.get('game_name', '')
                        if not llm_game_name or not re.search(r'[ぁ-んァ-ヶー一-龯]', llm_game_name):
                            result['game_name'] = japanese_title_from_readme
            except json.JSONDecodeError:
                logger.warning("Failed to parse LLM response")

        if result is None and japanese_title_from_readme:
            result = {
                'is_game': True,
                'game_name': japanese_title_from_readme,
                'product_id': None,
                'author': None,
                'platform': 'unknown'
            }

        return result


class MultiPlatformSearcher:
    """Searches for games on FANZA and SteamDB using Selenium"""

    def __init__(self, llm: LMStudioClient, enabled_platforms: Set[SearchPlatform]):
        self.llm = llm
        self.enabled_platforms = enabled_platforms
        self.driver = None
        self.chrome_pid = None

    def _build_chrome_options(self, headless: bool = True, use_proxy: bool = True) -> Options:
        """Build Chrome options with anti-detection settings"""
        chrome_options = Options()

        if headless:
            chrome_options.add_argument('--headless=new')

        # Anti-detection arguments
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)

        # Realistic user agent
        chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')

        # Additional options
        chrome_options.add_argument('--disable-infobars')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--lang=ja')

        # Use system proxy if available and requested
        # Note: Proxy often triggers Cloudflare on SteamDB, so use_proxy=False for SteamDB
        if use_proxy:
            try:
                import winreg
                reg_path = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
                reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path)
                proxy_server, _ = winreg.QueryValueEx(reg_key, 'ProxyServer')
                if proxy_server:
                    chrome_options.add_argument(f'--proxy-server={proxy_server}')
                    logger.info(f"Using proxy for Selenium: {proxy_server}")
            except:
                pass

        return chrome_options

    def _init_driver(self, headless: bool = True, use_proxy: bool = True) -> bool:
        """Initialize Selenium WebDriver"""
        if self.driver:
            return True

        try:
            chrome_options = self._build_chrome_options(headless, use_proxy)
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)

            try:
                self.chrome_pid = self.driver.service.process.pid
            except:
                pass

            # Apply selenium-stealth if available
            if STEALTH_AVAILABLE:
                stealth(self.driver,
                    languages=["ja", "en-US", "en"],
                    vendor="Google Inc.",
                    platform="Win32",
                    webgl_vendor="Intel Inc.",
                    renderer="Intel Iris OpenGL Engine",
                    fix_hairline=True,
                )
                logger.info("Applied selenium-stealth to driver")

            logger.info("Selenium WebDriver initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize Selenium: {e}")
            return False

    def _cleanup_driver(self):
        """Clean up Selenium WebDriver"""
        if self.driver:
            try:
                self.driver.quit()
                logger.debug("Driver quit() succeeded")
            except Exception as e:
                logger.debug(f"Driver quit() failed: {e}")

            if self.chrome_pid and sys.platform == 'win32':
                try:
                    subprocess.run(
                        ['taskkill', '/F', '/T', '/PID', str(self.chrome_pid)],
                        capture_output=True,
                        timeout=5
                    )
                except:
                    pass

            self.driver = None
            self.chrome_pid = None

    def _clean_search_terms_with_llm(self, folder_name: str, game_name: Optional[str] = None) -> List[str]:
        """Use LLM to extract clean search terms from folder name and game info"""

        prompt = f"""Extract clean search terms for a game search query.

Folder name: {folder_name}
Game name (if known): {game_name or 'Unknown'}

RULES:
1. Extract the core game title only
2. Remove version numbers (v1.0, Ver.2.0, etc.)
3. Remove dates ([240101], 2024-01-01, etc.)
4. Remove file extensions and technical terms
5. Remove brackets and their contents if they contain metadata
6. Keep Japanese titles intact
7. Remove common noise words: "Game", "Download", "Full", "Complete", "Edition"
8. If there's a Japanese title, prioritize it
9. Return 1-3 clean search terms, best first

OUTPUT FORMAT (JSON only, one line):
{{"search_terms": ["primary term", "alternative term"]}}"""

        logger.info("LLM cleaning search terms...")
        response = self.llm.query(prompt, temperature=0.2, max_tokens=512)

        clean_terms = []
        if response:
            try:
                json_match = re.search(r'\{[^}]*"search_terms"[^}]*\}', response, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group())
                    clean_terms = result.get('search_terms', [])
                    logger.info(f"LLM cleaned search terms: {clean_terms}")
            except json.JSONDecodeError:
                logger.warning("Failed to parse LLM search terms response")

        return clean_terms

    def _search_fanza_selenium(self, search_query: str) -> Optional[Dict]:
        """Search FANZA/DMM using Selenium"""
        if SearchPlatform.FANZA not in self.enabled_platforms:
            return None

        if not self._init_driver():
            return None

        logger.info(f"Searching FANZA with Selenium for: '{search_query}'")

        try:
            # Direct DMM search URL
            search_url = f"https://www.dmm.co.jp/mono/pcgame/-/search/=/searchstr={quote(search_query)}/"
            logger.info(f"FANZA search URL: {search_url}")

            self.driver.get(search_url)
            time.sleep(2)  # Wait for page to load

            # Handle age verification if present
            try:
                age_btn = WebDriverWait(self.driver, 3).until(
                    EC.element_to_be_clickable((By.XPATH, "//a[contains(text(), 'はい') or contains(text(), '18歳以上')]"))
                )
                age_btn.click()
                time.sleep(1)
            except:
                pass  # No age verification needed

            html = self.driver.page_source

            # Check for no results
            if '見つかりませんでした' in html or '0件' in html:
                logger.info("FANZA returned no results")
                return None

            # Extract product IDs from search results
            # Product ID formats: 1607aspc0153, 844miel044, d_123456, soft_123
            # Skip trial versions ending with _t
            patterns = [
                r'/cid=(\d+[a-z]+\d+)/',  # Format: 1607aspc0153, 844miel044
                r'/cid=(d_\d{4,8})/',  # Digital game: d_123456
                r'/cid=([a-z]+\d+)/',  # Format: soft123
                r'/cid=(\d+[a-z0-9]+)/',  # General alphanumeric
            ]

            for pattern in patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                if matches:
                    # Filter out trial versions (ending with _t) and duplicates
                    valid_matches = []
                    seen = set()
                    for m in matches:
                        if not m.endswith('_t') and m not in seen:
                            seen.add(m)
                            valid_matches.append(m)

                    if valid_matches:
                        product_id = valid_matches[0]
                        logger.info(f"FANZA found product ID: {product_id}")
                        return {
                            'platform': 'fanza',
                            'product_id': product_id,
                            'confidence': 'high',
                            'url': f"https://www.dmm.co.jp/mono/pcgame/-/detail/=/cid={product_id}/"
                        }

            if '件' in html or 'list' in html.lower():
                logger.info("FANZA has results but no standard product ID found")

            return None

        except Exception as e:
            logger.error(f"FANZA Selenium search failed: {e}")
            return None

    def _search_steamdb_selenium(self, search_query: str) -> Optional[Dict]:
        """Search SteamDB using Selenium"""
        if SearchPlatform.STEAMDB not in self.enabled_platforms:
            return None

        # SteamDB: use_proxy=False because proxy triggers Cloudflare challenge
        if not self._init_driver(use_proxy=False):
            return None

        logger.info(f"Searching SteamDB with Selenium for: '{search_query}'")

        try:
            # Direct SteamDB search URL
            search_url = f"https://steamdb.info/search/?a=all&q={quote(search_query)}"
            logger.info(f"SteamDB search URL: {search_url}")

            self.driver.get(search_url)

            # Handle Cloudflare challenge - wait for it to complete
            for attempt in range(6):  # Try up to 6 times (30 seconds total)
                time.sleep(5)
                html = self.driver.page_source

                # Check if still on Cloudflare challenge page
                if 'しばらくお待ちください' in html or 'Just a moment' in html or 'Checking your browser' in html:
                    logger.info(f"Cloudflare challenge detected, waiting... (attempt {attempt + 1}/6)")
                    continue
                else:
                    logger.info("Cloudflare challenge passed")
                    break
            else:
                logger.warning("Cloudflare challenge did not complete after 30 seconds")

            # Wait for search results table to load (SteamDB uses JavaScript)
            try:
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "table.table-products tbody tr, tr.app[data-appid], .panel-heading"))
                )
                logger.info("SteamDB page loaded")
            except:
                logger.warning("SteamDB results table not found, trying anyway...")

            # Additional wait for dynamic content
            time.sleep(2)

            html = self.driver.page_source

            # Check for "no results" error panel first
            if 'Nothing was found matching your request' in html:
                logger.info("SteamDB returned no results")
                return None

            # Method 1: Get app rows directly from DOM (most reliable)
            # Look for tr.app[data-appid] - actual game entries (skip packages/DLCs)
            try:
                app_rows = self.driver.find_elements(By.CSS_SELECTOR, "tr.app[data-appid]")
                for row in app_rows[:5]:  # Check first 5 app results
                    app_id = row.get_attribute("data-appid")
                    if app_id:
                        # Check if it's a DLC or Demo by looking at the row content
                        row_text = row.text.lower()
                        if 'dlc' in row_text or 'demo' in row_text:
                            logger.debug(f"Skipping DLC/Demo: AppID {app_id}")
                            continue

                        logger.info(f"SteamDB found AppID from table row: {app_id}")
                        return {
                            'platform': 'steam',
                            'product_id': app_id,
                            'confidence': 'high',
                            'url': f"https://store.steampowered.com/app/{app_id}"
                        }

                # If all results were DLCs/Demos, take the first one anyway
                if app_rows:
                    app_id = app_rows[0].get_attribute("data-appid")
                    if app_id:
                        logger.info(f"SteamDB found AppID (DLC/Demo): {app_id}")
                        return {
                            'platform': 'steam',
                            'product_id': app_id,
                            'confidence': 'medium',
                            'url': f"https://store.steampowered.com/app/{app_id}"
                        }
            except Exception as e:
                logger.debug(f"DOM tr.app search failed: {e}")

            # Method 2: Fallback - Extract data-appid from page source
            patterns = [
                r'<tr class="app" data-appid="(\d+)"',  # Table row with appid
                r'data-appid="(\d+)"',  # Any data-appid attribute
                r'href="https://steamdb\.info/app/(\d+)/"',  # SteamDB app link
                r'href="/app/(\d+)/"',  # Relative app link
            ]

            for pattern in patterns:
                matches = re.findall(pattern, html)
                if matches:
                    unique_matches = list(dict.fromkeys(matches))
                    app_id = unique_matches[0]
                    logger.info(f"SteamDB found AppID from HTML: {app_id}")
                    return {
                        'platform': 'steam',
                        'product_id': app_id,
                        'confidence': 'high',
                        'url': f"https://store.steampowered.com/app/{app_id}"
                    }

            # No results found - debug output
            if 'panel-heading' in html and 'Error' in html:
                logger.info("SteamDB returned no results (error panel)")
            elif 'Just a moment' in html or 'cf-browser-verification' in html:
                logger.warning("SteamDB blocked by Cloudflare challenge!")
                logger.info(f"HTML snippet: {html[:500]}")
            else:
                logger.info("SteamDB page loaded but no AppIDs found in HTML")
                logger.info(f"HTML length: {len(html)}, snippet: {html[:300]}")

            return None

        except Exception as e:
            logger.error(f"SteamDB Selenium search failed: {e}")
            return None

    def search_game(self, folder_name: str, game_name: Optional[str] = None,
                   search_terms: Optional[List[str]] = None) -> VerificationResult:
        """Multi-platform search to find game info"""

        logger.info("="*60)
        logger.info("MULTI-PLATFORM SELENIUM SEARCH")
        logger.info(f"Enabled platforms: {[p.value for p in self.enabled_platforms]}")
        logger.info("="*60)

        try:
            # Step 1: Use LLM to clean and extract search terms
            llm_clean_terms = self._clean_search_terms_with_llm(folder_name, game_name)

            # Step 2: Build search variations (LLM terms first, then fallbacks)
            search_variations = []

            # Add LLM-cleaned terms first (highest priority)
            search_variations.extend(llm_clean_terms)

            # Fallback: basic cleaning of game_name or folder_name
            base_query = game_name if game_name else folder_name
            base_query = re.sub(r'\s*[\[\(]?(ver|v|version)[\s\d\.]+.*$', '', base_query, flags=re.IGNORECASE)
            base_query = re.sub(r'[\[\(].*?[\]\)]', '', base_query)
            base_query = re.sub(r'_+', ' ', base_query).strip()
            if base_query:
                search_variations.append(base_query)

            # Add provided search terms
            if search_terms:
                search_variations.extend(search_terms)

            # Extract Japanese title if present
            japanese_match = re.search(r'[ぁ-んァ-ヶー一-龯]+[ぁ-んァ-ヶー一-龯\s・～〜\-]*', folder_name)
            if japanese_match:
                jp_title = japanese_match.group(0).strip()
                if jp_title not in search_variations:
                    search_variations.insert(0, jp_title)

            # Remove duplicates while preserving order
            seen = set()
            search_variations = [x for x in search_variations if x and not (x in seen or seen.add(x)) and len(x) >= 2]

            logger.info(f"Search variations: {search_variations}")

            # Step 3: Search each platform with each query
            for query in search_variations[:5]:
                logger.info(f"Trying search query: '{query}'")

                # Try FANZA first (uses proxy)
                if SearchPlatform.FANZA in self.enabled_platforms:
                    result = self._search_fanza_selenium(query)
                    if result:
                        return VerificationResult(
                            is_found=True,
                            platform='fanza',
                            confidence=result['confidence'],
                            product_id=result['product_id'],
                            game_name=game_name,
                            sources=[VerificationSource.FANZA_SEARCH],
                            reasoning=f"Found on FANZA: {result['product_id']}",
                            url=result['url']
                        )
                    # Cleanup driver after FANZA since SteamDB needs different settings (no proxy)
                    self._cleanup_driver()

                # Try SteamDB (no proxy - to avoid Cloudflare)
                if SearchPlatform.STEAMDB in self.enabled_platforms:
                    result = self._search_steamdb_selenium(query)
                    if result:
                        return VerificationResult(
                            is_found=True,
                            platform='steam',
                            confidence=result['confidence'],
                            product_id=result['product_id'],
                            game_name=game_name,
                            sources=[VerificationSource.STEAMDB_SEARCH],
                            reasoning=f"Found on Steam: AppID {result['product_id']}",
                            url=result['url']
                        )

                # Rate limit between queries
                time.sleep(1)

            return VerificationResult(
                is_found=False,
                confidence='low',
                reasoning='No results found on any enabled platform'
            )

        finally:
            # Clean up driver after search
            self._cleanup_driver()


class PlatformScraper:
    """Scrapes metadata from FANZA and Steam pages"""

    def __init__(self):
        self.session = requests.Session()
        self._setup_proxy()

    def _setup_proxy(self):
        """Set up proxy"""
        try:
            import winreg
            reg_path = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path)
            proxy_server, _ = winreg.QueryValueEx(reg_key, 'ProxyServer')

            if proxy_server:
                proxies = {
                    'http': f'http://{proxy_server}',
                    'https': f'http://{proxy_server}'
                }
                self.session.proxies.update(proxies)
        except:
            pass

    def scrape_fanza(self, product_id: str) -> Optional[Dict]:
        """Scrape metadata from FANZA/DMM"""
        url = f"https://www.dmm.co.jp/mono/pcgame/-/detail/=/cid={product_id}/"

        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Cookie': 'age_check_done=1'
            }

            response = self.session.get(url, headers=headers, timeout=15)
            html = response.text

            # Extract title
            title_match = re.search(r'<h1[^>]*id="title"[^>]*>([^<]+)</h1>', html)
            if not title_match:
                title_match = re.search(r'<title>([^<|]+)', html)
            game_name = title_match.group(1).strip() if title_match else None

            # Extract maker/circle
            maker_match = re.search(r'メーカー[：:].*?<a[^>]*>([^<]+)</a>', html, re.DOTALL)
            author = maker_match.group(1).strip() if maker_match else None

            # Extract release date
            date_match = re.search(r'発売日[：:].*?(\d{4})/(\d{2})/(\d{2})', html, re.DOTALL)
            release_date = None
            if date_match:
                year, month, day = date_match.groups()
                release_date = f"{year[-2:]}{month}{day}"

            return {
                'product_id': product_id,
                'game_name': game_name,
                'author': author,
                'release_date': release_date,
                'url': url,
                'platform': 'fanza'
            }

        except Exception as e:
            logger.error(f"Failed to scrape FANZA: {e}")
            return None

    def scrape_steam(self, app_id: str) -> Optional[Dict]:
        """Scrape metadata from Steam"""
        url = f"https://store.steampowered.com/api/appdetails?appids={app_id}&l=japanese"

        try:
            response = self.session.get(url, timeout=15)
            data = response.json()

            if not data.get(app_id, {}).get('success'):
                return None

            app_data = data[app_id]['data']

            game_name = app_data.get('name')
            author = app_data.get('developers', [None])[0] if app_data.get('developers') else None

            # Parse release date
            release_date = None
            release_info = app_data.get('release_date', {})
            if release_info.get('date'):
                date_str = release_info['date']
                # Try various date formats
                for fmt in ['%Y年%m月%d日', '%b %d, %Y', '%d %b, %Y']:
                    try:
                        dt = datetime.strptime(date_str, fmt)
                        release_date = dt.strftime('%y%m%d')
                        break
                    except ValueError:
                        continue

            return {
                'product_id': app_id,
                'game_name': game_name,
                'author': author,
                'release_date': release_date,
                'url': f"https://store.steampowered.com/app/{app_id}",
                'platform': 'steam'
            }

        except Exception as e:
            logger.error(f"Failed to scrape Steam: {e}")
            return None


class GameRenamer:
    """Main orchestrator for the renaming process"""

    def __init__(self, parent_folder: str, enabled_platforms: Set[SearchPlatform], viewer_port: int = 5001):
        self.parent_folder = parent_folder
        self.enabled_platforms = enabled_platforms
        self.viewer_port = viewer_port

        # Initialize components
        self.llm = LMStudioClient()
        if not self.llm.check_connection():
            raise RuntimeError("LMStudio not running on localhost:1234")

        self.folder_analyzer = FolderAnalyzer(self.llm)
        self.game_identifier = GameIdentifier(self.llm)
        self.searcher = MultiPlatformSearcher(self.llm, enabled_platforms)
        self.scraper = PlatformScraper()

        self.results = {
            'renamed': [],
            'skipped': [],
            'moved_unidentified': [],
            'errors': []
        }

        self._save_results()

    def _start_viewer(self):
        """Start the rename viewer as a separate process"""
        try:
            viewer_path = os.path.join(os.path.dirname(__file__), 'rename_viewer.py')

            if not os.path.exists(viewer_path):
                logger.warning("rename_viewer.py not found, skipping viewer auto-start")
                return

            if sys.platform == 'win32':
                CREATE_NEW_PROCESS_GROUP = 0x00000200
                DETACHED_PROCESS = 0x00000008
                subprocess.Popen(
                    [sys.executable, viewer_path, self.parent_folder, '--port', str(self.viewer_port)],
                    creationflags=CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL
                )
            else:
                subprocess.Popen(
                    [sys.executable, viewer_path, self.parent_folder, '--port', str(self.viewer_port)],
                    start_new_session=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL
                )

            logger.info(f"Started rename viewer at http://127.0.0.1:{self.viewer_port}")
            time.sleep(1)
            webbrowser.open(f'http://127.0.0.1:{self.viewer_port}')

        except Exception as e:
            logger.warning(f"Could not start viewer: {e}")

    def _extract_product_id_from_folder_name(self, folder_name: str) -> Optional[Dict]:
        """Extract product ID from folder name"""
        # FANZA patterns
        fanza_patterns = [
            (r'\b(d_\d{4,8})\b', 'fanza'),
            (r'\b(h_\d{4,8}[a-z]*\d*)\b', 'fanza'),
        ]

        # Steam patterns
        steam_patterns = [
            (r'\bAppID[_\-\s]*(\d{4,7})\b', 'steam'),
            (r'\bSteam[_\-\s]*(\d{4,7})\b', 'steam'),
        ]

        for pattern, platform in fanza_patterns + steam_patterns:
            match = re.search(pattern, folder_name, re.IGNORECASE)
            if match:
                product_id = match.group(1)
                logger.info(f"Found {platform} product ID in folder name: {product_id}")
                return {'product_id': product_id, 'platform': platform}

        return None

    def _move_to_unidentified_folder(self, folder_path: str) -> bool:
        """Move unidentified folders to UNIDENTIFIED directory"""
        folder_name = os.path.basename(folder_path)
        parent_dir = os.path.dirname(folder_path)

        unidentified_dir = os.path.join(parent_dir, "UNIDENTIFIED")

        try:
            if not os.path.exists(unidentified_dir):
                os.makedirs(unidentified_dir)
                logger.info(f"Created UNIDENTIFIED directory: {unidentified_dir}")

            destination = os.path.join(unidentified_dir, folder_name)

            if os.path.exists(destination):
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                destination = os.path.join(unidentified_dir, f"{folder_name}_{timestamp}")

            import shutil
            shutil.move(folder_path, destination)

            logger.info(f"Moved to UNIDENTIFIED: {folder_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to move {folder_name}: {e}")
            return False

    def run(self):
        """Main execution loop"""
        logger.info(f"Starting game folder analysis in: {self.parent_folder}")
        logger.info(f"Enabled platforms: {[p.value for p in self.enabled_platforms]}")

        logger.info("Starting rename viewer...")
        self._start_viewer()

        folders = self._get_folders()
        logger.info(f"Found {len(folders)} folders to process")

        for i, folder_path in enumerate(folders, 1):
            folder_name = os.path.basename(folder_path)
            logger.info(f"\n{'='*60}")
            logger.info(f"[{i}/{len(folders)}] Processing: {folder_name}")
            logger.info(f"{'='*60}")

            try:
                self._process_folder(folder_path)
            except Exception as e:
                logger.error(f"Error processing {folder_name}: {e}")
                self.results['errors'].append({
                    'folder': folder_name,
                    'error': str(e)
                })
                self._save_results()

        self._print_summary()
        self._save_results()

        logger.info("\nProcessing complete! Viewer will continue running.")
        logger.info("Press Ctrl+C to exit")

    def _get_folders(self) -> List[str]:
        """Get all folders in parent directory"""
        folders = []
        try:
            for item in os.listdir(self.parent_folder):
                item_path = os.path.join(self.parent_folder, item)
                if os.path.isdir(item_path):
                    if item not in {'.', '..', '__pycache__', 'UNIDENTIFIED', 'templates'}:
                        folders.append(item_path)
        except Exception as e:
            logger.error(f"Error reading parent folder: {e}")

        return sorted(folders)

    def _process_folder(self, folder_path: str):
        """Process a single folder - simplified: just use folder name for search"""
        folder_name = os.path.basename(folder_path)

        # Step 1: Check for product ID already in folder name
        folder_id_result = self._extract_product_id_from_folder_name(folder_name)

        # Step 2: Search directly using folder name (LLM cleaning happens inside search_game)
        search_result = self.searcher.search_game(folder_name)

        # Combine results
        product_id = None
        platform = None
        metadata = None

        if folder_id_result:
            product_id = folder_id_result['product_id']
            platform = folder_id_result['platform']
        elif search_result.is_found:
            product_id = search_result.product_id
            platform = search_result.platform

        # Step 3: Scrape full metadata if we have a product ID
        if product_id and platform:
            logger.info(f"Fetching metadata for {platform} product: {product_id}")

            if platform == 'fanza':
                metadata = self.scraper.scrape_fanza(product_id)
            elif platform == 'steam':
                metadata = self.scraper.scrape_steam(product_id)

        # Step 4: Decide what to do
        if not product_id or not metadata:
            logger.warning("Could not identify game - moving to UNIDENTIFIED")
            if self._move_to_unidentified_folder(folder_path):
                self.results['moved_unidentified'].append({
                    'folder': folder_name,
                    'reason': 'Could not find on any enabled platform'
                })
            else:
                self.results['errors'].append({
                    'folder': folder_name,
                    'error': 'Failed to move to UNIDENTIFIED'
                })
            self._save_results()
            return

        # Step 5: Rename folder
        game_name = metadata.get('game_name') or folder_name
        author = metadata.get('author')
        release_date = metadata.get('release_date')

        success = self._rename_folder(
            folder_path,
            product_id,
            game_name,
            author,
            release_date,
            platform,
            metadata.get('url')
        )

        if success:
            logger.info(f"Successfully renamed!")
        else:
            logger.error("Rename failed")

    def _verify_rename_with_llm(self, folder_name: str, new_name: str,
                                 game_name: str, product_id: str,
                                 platform: str, author: Optional[str] = None) -> bool:
        """Ask LLM to verify if the rename makes sense"""

        prompt = f"""Verify if this game folder rename is correct.

ORIGINAL FOLDER: {folder_name}
NEW NAME: {new_name}

EXTRACTED INFO:
- Game title: {game_name}
- Product ID: {product_id}
- Platform: {platform}
- Author/Developer: {author or 'Unknown'}

VERIFICATION RULES:
1. Does the new name contain recognizable parts from the original folder name?
2. Does the game title in the new name make sense (not gibberish)?
3. Is the product ID format valid for the platform?
   - FANZA: d_XXXXX or similar
   - Steam: numeric AppID (4-7 digits)
4. Is it likely the same game or a false positive match?

Answer with JSON only:
{{"approved": true/false, "reason": "brief explanation"}}"""

        logger.info("="*60)
        logger.info("LLM RENAME VERIFICATION")
        logger.info("="*60)
        logger.info(f"Original: {folder_name}")
        logger.info(f"New name: {new_name}")

        response = self.llm.query(prompt, temperature=0.1, max_tokens=512)

        if response:
            try:
                json_match = re.search(r'\{[^}]*"approved"[^}]*\}', response, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group())
                    approved = result.get('approved', False)
                    reason = result.get('reason', 'No reason provided')

                    logger.info(f"LLM DECISION: {'APPROVED' if approved else 'REJECTED'}")
                    logger.info(f"Reason: {reason}")
                    logger.info("="*60)

                    return approved
            except json.JSONDecodeError:
                logger.warning("Failed to parse LLM verification response")

        # Default to approve if LLM fails
        logger.warning("LLM verification failed, defaulting to approve")
        return True

    def _rename_folder(self, folder_path: str, product_id: str, game_name: str,
                      author: Optional[str], release_date: Optional[str],
                      platform: str, url: Optional[str]) -> bool:
        """Rename the folder to standardized format"""

        folder_name = os.path.basename(folder_path)
        date_str = release_date if release_date else datetime.now().strftime('%y%m%d')

        # Clean names for filesystem
        safe_name = re.sub(r'[<>:"/\\|?*]', '', game_name).strip()

        # Build new name: [date][platform:product_id][author]game_name
        platform_prefix = platform[0].upper()  # F for FANZA, S for Steam

        if author:
            safe_author = re.sub(r'[<>:"/\\|?*]', '', author).strip()
            new_name = f"[{date_str}][{platform_prefix}:{product_id}][{safe_author}]{safe_name}"
        else:
            new_name = f"[{date_str}][{platform_prefix}:{product_id}]{safe_name}"

        new_path = os.path.join(os.path.dirname(folder_path), new_name)

        # Avoid duplicates
        if os.path.exists(new_path):
            new_name = f"{new_name}_{datetime.now().strftime('%H%M%S')}"
            new_path = os.path.join(os.path.dirname(folder_path), new_name)

        # Skip if already correct
        if folder_name == new_name:
            logger.info("Folder already in correct format")
            self.results['skipped'].append({
                'folder': folder_name,
                'reason': 'Already in correct format'
            })
            self._save_results()
            return True

        # LLM verification before renaming
        if not self._verify_rename_with_llm(folder_name, new_name, game_name, product_id, platform, author):
            logger.warning("LLM rejected the rename - moving to UNIDENTIFIED")
            if self._move_to_unidentified_folder(folder_path):
                self.results['moved_unidentified'].append({
                    'folder': folder_name,
                    'reason': f'LLM verification failed for rename to: {new_name}'
                })
            else:
                self.results['errors'].append({
                    'folder': folder_name,
                    'error': 'LLM rejected rename and failed to move to UNIDENTIFIED'
                })
            self._save_results()
            return False

        try:
            os.rename(folder_path, new_path)

            self.results['renamed'].append({
                'original': folder_name,
                'new_name': new_name,
                'product_id': product_id,
                'game_name': game_name,
                'author': author,
                'release_date': release_date,
                'platform': platform,
                'url': url
            })

            self._save_results()
            return True

        except Exception as e:
            logger.error(f"Rename failed: {e}")
            self.results['errors'].append({
                'folder': folder_name,
                'error': f'Rename failed: {str(e)}'
            })
            self._save_results()
            return False

    def _save_results(self):
        """Save results to JSON"""
        output_file = os.path.join(self.parent_folder, 'rename_results.json')
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save results: {e}")

    def _print_summary(self):
        """Print summary"""
        print("\n" + "="*60)
        print("RENAMING SUMMARY")
        print("="*60)

        print(f"\nRenamed: {len(self.results['renamed'])}")
        for item in self.results['renamed']:
            print(f"  {item['original']}")
            print(f"    -> {item['new_name']}")

        print(f"\nMoved to UNIDENTIFIED: {len(self.results['moved_unidentified'])}")

        if self.results['errors']:
            print(f"\nErrors: {len(self.results['errors'])}")
            for item in self.results['errors']:
                print(f"  {item['folder']}: {item['error']}")

        print("\n" + "="*60)


def setup_logging(log_dir: str):
    """Set up logging"""
    log_file = os.path.join(log_dir, 'game_renamer.log')

    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    stream_handler = logging.StreamHandler(sys.stdout)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[file_handler, stream_handler],
        force=True
    )

    logger.info(f"Logging to: {log_file}")


def select_platforms() -> Set[SearchPlatform]:
    """Interactive platform selection at startup"""
    print("\nSelect search platforms:")
    print("  1. FANZA only")
    print("  2. SteamDB only")
    print("  3. Both FANZA and SteamDB (default)")
    print()

    while True:
        choice = input("Enter choice [1/2/3]: ").strip()

        if choice == '1':
            print("Selected: FANZA only")
            return {SearchPlatform.FANZA}
        elif choice == '2':
            print("Selected: SteamDB only")
            return {SearchPlatform.STEAMDB}
        elif choice == '3' or choice == '':
            print("Selected: Both FANZA and SteamDB")
            return {SearchPlatform.FANZA, SearchPlatform.STEAMDB}
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


def select_directory() -> str:
    """Interactive directory selection at startup"""
    script_dir = os.path.dirname(__file__)
    default_folder = os.path.join(script_dir, 'sample pages')

    print("\nSelect parent directory:")
    print(f"  1. Default: sample pages")
    print("  2. Enter custom path")
    print()

    while True:
        choice = input("Enter choice [1/2]: ").strip()

        if choice == '1' or choice == '':
            if os.path.exists(default_folder):
                print(f"Selected: {default_folder}")
                return default_folder
            else:
                print(f"Default folder does not exist. Creating: {default_folder}")
                os.makedirs(default_folder, exist_ok=True)
                print(f"Selected: {default_folder}")
                return default_folder
        elif choice == '2':
            custom_path = input("Enter path: ").strip().strip('"').strip("'")
            if custom_path and os.path.isdir(custom_path):
                print(f"Selected: {custom_path}")
                return custom_path
            elif custom_path:
                print(f"Error: '{custom_path}' is not a valid directory. Try again.")
            else:
                print("Error: No path provided. Try again.")
        else:
            print("Invalid choice. Please enter 1 or 2.")


def main():
    """Entry point"""
    parser = argparse.ArgumentParser(
        description='FANZA/SteamDB Game Folder Renamer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python game_renamer.py
  python game_renamer.py "E:\\Games\\New"
  python game_renamer.py --fanza-only
  python game_renamer.py --steam-only
        '''
    )
    parser.add_argument(
        'parent_folder',
        type=str,
        nargs='?',
        help='Path to the parent folder containing game folders to rename'
    )
    parser.add_argument(
        '--viewer-port',
        type=int,
        default=5001,
        help='Port to run the viewer on (default: 5001)'
    )
    parser.add_argument(
        '--fanza-only',
        action='store_true',
        help='Search FANZA only (skip interactive prompt)'
    )
    parser.add_argument(
        '--steam-only',
        action='store_true',
        help='Search SteamDB only (skip interactive prompt)'
    )
    parser.add_argument(
        '--both',
        action='store_true',
        help='Search both platforms (skip interactive prompt)'
    )

    args = parser.parse_args()

    # Show header for interactive mode
    if not args.parent_folder and not (args.fanza_only or args.steam_only or args.both):
        print("="*60)
        print("FANZA/SteamDB Game Folder Renamer")
        print("="*60)

    # Determine folder first (so user knows what they're working with)
    if args.parent_folder:
        parent_folder = args.parent_folder
    else:
        parent_folder = select_directory()

    # Determine platforms
    if args.fanza_only:
        enabled_platforms = {SearchPlatform.FANZA}
    elif args.steam_only:
        enabled_platforms = {SearchPlatform.STEAMDB}
    elif args.both:
        enabled_platforms = {SearchPlatform.FANZA, SearchPlatform.STEAMDB}
    else:
        enabled_platforms = select_platforms()

    # Validate folder
    if not parent_folder:
        print("Error: No path provided")
        sys.exit(1)

    if not os.path.exists(parent_folder):
        print(f"Error: Directory '{parent_folder}' does not exist")
        sys.exit(1)

    if not os.path.isdir(parent_folder):
        print(f"Error: '{parent_folder}' is not a directory")
        sys.exit(1)

    # Set up logging
    setup_logging(parent_folder)

    logger.info("="*60)
    logger.info("FANZA/SteamDB Game Folder Renamer")
    logger.info("="*60)
    logger.info(f"Processing directory: {parent_folder}")
    logger.info(f"Enabled platforms: {[p.value for p in enabled_platforms]}")

    try:
        renamer = GameRenamer(parent_folder, enabled_platforms, viewer_port=args.viewer_port)
        renamer.run()

        logger.info(f"\nViewer is still running at http://127.0.0.1:{args.viewer_port}")
        logger.info("Press Ctrl+C to exit")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("\nShutting down...")

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)


if __name__ == "__main__":
    main()
