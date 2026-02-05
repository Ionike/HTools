#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DLsite Game Folder Renamer - DDG + EXE Version
Simple workflow: Extract exe title -> DuckDuckGo search -> DLsite metadata
No LLM required.
Format: [YYMMDD][RJ########][Author]Game Name
"""

import os
import json
import re
import sys
import time
import subprocess
import webbrowser
from datetime import datetime
from typing import Optional, Dict, List
from dataclasses import dataclass, field
from enum import Enum
import logging
import argparse

# Force UTF-8 encoding for console output to handle Japanese characters
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Logger will be configured in main() after we know the processing directory
logger = logging.getLogger(__name__)

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import requests
    from urllib.parse import quote
except ImportError as e:
    logger.error(f"Required packages not installed. Install with: pip install requests")
    logger.error(f"Import error: {e}")
    sys.exit(1)

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    logger.warning("Selenium not available. Install with: pip install selenium")


# Verification system data structures
class VerificationSource(Enum):
    """Sources used for game verification"""
    REGEX_FOLDER_NAME = "regex_folder_name"
    EXE_TITLE = "exe_title"
    CONFIG_FILE = "config_file"
    DUCKDUCKGO_SEARCH = "duckduckgo_search"


@dataclass
class VerificationResult:
    """Result from verification process"""
    is_dlsite: bool
    confidence: str  # 'high', 'medium', 'low'
    rj_number: Optional[str] = None
    game_name: Optional[str] = None
    author: Optional[str] = None
    sources: List[VerificationSource] = field(default_factory=list)
    reasoning: str = ""


class DDGSearcher:
    """Searches for game on DLsite via DuckDuckGo using a headed browser to avoid rate limits"""

    def __init__(self):
        self.driver = None
        if not SELENIUM_AVAILABLE:
            logger.error("Selenium is required for browser-based DDG search. Install with: pip install selenium")
            sys.exit(1)
        logger.info("Initializing browser for DuckDuckGo searches...")
        self._init_browser()

    def _init_browser(self):
        """Initialize a headed browser (tries Chrome first, then Firefox)"""
        # Try Chrome first
        logger.info("Attempting to initialize Chrome browser...")
        try:
            options = ChromeOptions()
            options.add_argument('--disable-blink-features=AutomationControlled')
            options.add_argument('--lang=ja')
            options.add_argument('--no-first-run')
            options.add_argument('--no-default-browser-check')
            options.add_experimental_option('excludeSwitches', ['enable-automation', 'enable-logging'])
            options.add_experimental_option('useAutomationExtension', False)
            self.driver = webdriver.Chrome(options=options)
            self.driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                'source': 'Object.defineProperty(navigator, "webdriver", {get: () => undefined})'
            })
            logger.info("Browser initialized: Chrome (headed)")
            return
        except Exception as e:
            logger.warning(f"Chrome init failed: {e}")

        # Fallback to Firefox
        logger.info("Attempting to initialize Firefox browser...")
        try:
            options = FirefoxOptions()
            options.set_preference('intl.accept_languages', 'ja,en-US,en')
            self.driver = webdriver.Firefox(options=options)
            logger.info("Browser initialized: Firefox (headed)")
            return
        except Exception as e:
            logger.warning(f"Firefox init failed: {e}")

        logger.error("Could not initialize any browser. Install Chrome or Firefox WebDriver.")
        sys.exit(1)

    def close(self):
        """Close the browser"""
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None

    def search_duckduckgo(self, search_query: str) -> Optional[str]:
        """
        Use DuckDuckGo search via headed browser to find DLsite games.
        Returns RJ number if found.
        """
        logger.info(f"DuckDuckGo search: '{search_query}'")

        try:
            ddg_url = f"https://duckduckgo.com/?q={quote(search_query + ' site:dlsite.com')}"
            logger.debug(f"DuckDuckGo URL: {ddg_url}")

            self.driver.get(ddg_url)

            # Wait for results to load
            try:
                WebDriverWait(self.driver, 15).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, '[data-result], .result, .results, #links'))
                )
            except Exception:
                # Even if wait times out, try to parse whatever we have
                time.sleep(3)

            html = self.driver.page_source

            # Look for RJ codes in the HTML
            patterns = [
                r'dlsite\.com/[^"\'<>\s]*/work/[^"\'<>\s]*/product_id/(RJ\d{6,8})',
                r'dlsite\.com[^"\'<>\s]*(RJ\d{6,8})',
                r'\b(RJ\d{6,8})\b',
            ]

            for pattern in patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                if matches:
                    rj_number = matches[0] if isinstance(matches[0], str) else matches[0]
                    if not rj_number.startswith('RJ'):
                        rj_number = 'RJ' + rj_number
                    logger.info(f"✓ DuckDuckGo found RJ code: {rj_number}")
                    return rj_number.upper()

            logger.info("DuckDuckGo found no RJ codes")
            return None

        except Exception as e:
            logger.error(f"DuckDuckGo search failed: {e}")
            # Try to reinitialize browser if it crashed
            try:
                self.driver.title
            except Exception:
                logger.info("Browser seems dead, reinitializing...")
                self.close()
                self._init_browser()
            return None

    def search_with_variations(self, search_terms: List[str]) -> Optional[str]:
        """
        Try multiple search variations to find the game.
        Returns RJ number if found.
        """
        import random

        # Known garbage strings from PE header misinterpretation
        garbage_patterns = [
            '桔獩瀠潲牧浡挠湡潮',  # "This program canno" as UTF-16
            '桔獩瀠潲牧慲',        # Partial variant
            '獩瀠潲牧浡',          # Partial variant
        ]

        # Remove duplicates while preserving order, and filter garbage
        seen = set()
        unique_terms = []
        for x in search_terms:
            if not x or x in seen or len(x) < 2:
                continue
            # Skip if contains known garbage
            if any(garbage in x for garbage in garbage_patterns):
                logger.debug(f"Filtered garbage string: {x}")
                continue
            seen.add(x)
            unique_terms.append(x)

        for i, term in enumerate(unique_terms, 1):
            logger.info(f"Search attempt {i}/{len(unique_terms)}: '{term}'")
            rj_number = self.search_duckduckgo(term)

            if rj_number:
                return rj_number

            # Small delay between searches
            if i < len(unique_terms):
                time.sleep(random.uniform(1.5, 3.0))

        return None


class DLsiteScraper:
    """Scrapes metadata from DLsite pages"""

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

    def scrape_metadata(self, rj_number: str) -> Optional[Dict]:
        """Extract metadata from DLsite product page"""
        url = f"https://www.dlsite.com/maniax/work/=/product_id/{rj_number}.html"

        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }

            response = self.session.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            html = response.text

            # Extract game name from og:title meta tag
            og_title_match = re.search(r'<meta\s+property="og:title"\s+content="([^"]+)"', html)
            if og_title_match:
                game_name = og_title_match.group(1)
                game_name = re.sub(r'\s*\|\s*DLsite.*$', '', game_name)
                game_name = re.sub(r'\s*\[[^\]]+\]\s*$', '', game_name)
                game_name = re.sub(r'【[^】]+版】', '', game_name)
                game_name = game_name.strip()
            else:
                title_match = re.search(r'<title>([^<]+)</title>', html)
                game_name = title_match.group(1).strip() if title_match else None
                if game_name:
                    game_name = re.sub(r'\s*[\|｜].*$', '', game_name).strip()
                    game_name = re.sub(r'【[^】]+版】', '', game_name).strip()

            # Extract circle name
            circle_patterns = [
                r'<th>サークル名</th>\s*<td[^>]*>.*?<a[^>]*>([^<]+)</a>',
                r'<th>サークル</th>\s*<td[^>]*>.*?<a[^>]*>([^<]+)</a>',
            ]
            author = None
            for pattern in circle_patterns:
                match = re.search(pattern, html, re.DOTALL)
                if match:
                    author = match.group(1).strip()
                    break

            # Extract release date
            date_patterns = [
                r'<th>販売日</th>\s*<td[^>]*>.*?(\d{4})年(\d{1,2})月(\d{1,2})日',
                r'<th>配信開始日</th>\s*<td[^>]*>.*?(\d{4})年(\d{1,2})月(\d{1,2})日',
            ]
            release_date = None
            for pattern in date_patterns:
                match = re.search(pattern, html, re.DOTALL)
                if match:
                    year, month, day = match.groups()
                    release_date = f"{year[-2:]}{month.zfill(2)}{day.zfill(2)}"
                    break

            metadata = {
                'rj_number': rj_number,
                'game_name': game_name,
                'author': author,
                'release_date': release_date,
                'url': url
            }

            logger.info(f"Scraped metadata: {metadata}")
            return metadata

        except Exception as e:
            logger.error(f"Failed to scrape {url}: {e}")
            return None


class GameRenamer:
    """Main orchestrator for the renaming process"""

    def __init__(self, parent_folder: str):
        self.parent_folder = parent_folder
        self.searcher = DDGSearcher()
        self.scraper = DLsiteScraper()

        self.results = {
            'renamed': [],
            'skipped': [],
            'moved_non_dlsite': [],
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
                    [sys.executable, viewer_path, self.parent_folder, '--port', '5000'],
                    creationflags=CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL
                )
            else:
                subprocess.Popen(
                    [sys.executable, viewer_path, self.parent_folder, '--port', '5000'],
                    start_new_session=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL
                )

            logger.info("Started rename viewer at http://127.0.0.1:5000")
            time.sleep(1)
            webbrowser.open('http://127.0.0.1:5000')

        except Exception as e:
            logger.warning(f"Could not start viewer: {e}")

    def _get_folder_contents(self, folder_path: str) -> Dict:
        """Get all files in folder with categorization"""
        contents = {
            'all_files': [],
            'executables': [],
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

        except Exception as e:
            logger.error(f"Error reading folder {folder_path}: {e}")

        return contents

    def _extract_rj_from_folder_name(self, folder_name: str) -> Optional[str]:
        """Extract RJ code from folder name using regex"""
        patterns = [
            r'\b(RJ\d{8})\b',
            r'\b(RJ\d{6})\b',
            r'(RJ\d{6,8})',
        ]

        for pattern in patterns:
            match = re.search(pattern, folder_name, re.IGNORECASE)
            if match:
                rj_code = match.group(1).upper()
                logger.info(f"Regex extracted RJ code from folder name: {rj_code}")
                return rj_code

        return None

    def _clean_game_title(self, title: str) -> Optional[str]:
        """Clean up game title by removing control instructions and cruft"""
        if not title:
            return None

        split_patterns = [
            r'　　',
            r'  ',
            r'\s*enter[：:]',
            r'\s*esc[：:]',
            r'\s*↑↓←→',
            r'\s*【',
            r'\s*\[操作\]',
            r'\s*操作方法',
            r'\s*決定[：:]',
        ]

        cleaned = title
        for pattern in split_patterns:
            match = re.search(pattern, cleaned, re.IGNORECASE)
            if match:
                cleaned = cleaned[:match.start()].strip()
                if cleaned:
                    break

        if cleaned and len(cleaned) >= 2:
            return cleaned
        elif len(title) <= 100:
            return title.strip()
        else:
            return title[:100].strip()

    def _extract_game_title_from_config(self, folder_path: str) -> Optional[str]:
        """Extract game title from engine config files (RPG Maker, NW.js, etc.)"""
        title = None

        # 1. RPG Maker MV/MZ: www/data/System.json
        for system_path in [
            os.path.join(folder_path, 'www', 'data', 'System.json'),
            os.path.join(folder_path, 'data', 'System.json'),
        ]:
            if os.path.exists(system_path):
                try:
                    with open(system_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if 'gameTitle' in data and data['gameTitle']:
                            title = data['gameTitle'].strip()
                            logger.info(f"Found game title in System.json: '{title}'")
                            return self._clean_game_title(title)
                except Exception as e:
                    logger.debug(f"Failed to read System.json: {e}")

        # Check subdirectories
        for root, dirs, files in os.walk(folder_path):
            if root.count(os.sep) - folder_path.count(os.sep) > 3:
                break
            for fname in files:
                if fname.lower() == 'system.json':
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            if 'gameTitle' in data and data['gameTitle']:
                                title = data['gameTitle'].strip()
                                logger.info(f"Found game title in {fpath}: '{title}'")
                                return self._clean_game_title(title)
                    except:
                        pass

        # 2. RPG Maker VX/VXAce/XP: Game.ini or RPG_RT.ini
        for ini_name in ['Game.ini', 'RPG_RT.ini']:
            for root, dirs, files in os.walk(folder_path):
                if root.count(os.sep) - folder_path.count(os.sep) > 3:
                    break
                if ini_name in files:
                    ini_path = os.path.join(root, ini_name)
                    try:
                        for enc in ['utf-8', 'shift-jis', 'cp932']:
                            try:
                                with open(ini_path, 'r', encoding=enc) as f:
                                    content = f.read()
                                    match = re.search(r'^(?:Title|GameTitle)\s*=\s*(.+)$', content, re.MULTILINE)
                                    if match:
                                        title = match.group(1).strip()
                                        if title and title.lower() not in ['game', 'untitled']:
                                            logger.info(f"Found game title in {ini_name}: '{title}'")
                                            return self._clean_game_title(title)
                                break
                            except UnicodeDecodeError:
                                continue
                    except Exception as e:
                        logger.debug(f"Failed to read {ini_name}: {e}")

        # 3. NW.js/Electron games: package.json
        for root, dirs, files in os.walk(folder_path):
            if root.count(os.sep) - folder_path.count(os.sep) > 3:
                break
            if 'package.json' in files:
                pkg_path = os.path.join(root, 'package.json')
                try:
                    with open(pkg_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if 'window' in data and isinstance(data['window'], dict):
                            if 'title' in data['window'] and data['window']['title']:
                                title = data['window']['title'].strip()
                                if title.lower() not in ['game', 'nw.js']:
                                    logger.info(f"Found game title in package.json: '{title}'")
                                    return self._clean_game_title(title)
                        if 'name' in data and data['name']:
                            name = data['name'].strip()
                            if name.lower() not in ['game', 'nw', 'app', 'electron']:
                                if re.search(r'[ぁ-んァ-ヶー一-龯]', name):
                                    logger.info(f"Found game title in package.json name: '{name}'")
                                    return self._clean_game_title(name)
                except Exception as e:
                    logger.debug(f"Failed to read package.json: {e}")

        return None

    def _extract_exe_version_info(self, exe_path: str) -> Dict[str, str]:
        """Extract Windows PE version info"""
        version_info = {}

        if not PEFILE_AVAILABLE:
            logger.debug("pefile not available, skipping PE version info extraction")
            return version_info

        try:
            pe = pefile.PE(exe_path, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

            if hasattr(pe, 'FileInfo'):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, '__iter__'):
                        for info in file_info:
                            if hasattr(info, 'StringTable'):
                                for st in info.StringTable:
                                    for key, value in st.entries.items():
                                        try:
                                            key_str = key.decode('utf-8', errors='ignore') if isinstance(key, bytes) else str(key)
                                            val_str = value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else str(value)
                                            if val_str.strip():
                                                version_info[key_str] = val_str.strip()
                                        except:
                                            pass
            pe.close()

            if version_info:
                logger.info(f"Extracted PE version info: {version_info}")

        except Exception as e:
            logger.debug(f"Failed to extract PE version info: {e}")

        return version_info

    def _extract_exe_strings(self, exe_path: str, min_len: int = 4) -> List[str]:
        """Extract strings from executable file including UTF-16 for Japanese titles"""
        useful_strings = []

        try:
            with open(exe_path, "rb") as f:
                data = f.read()

            # Extract UTF-16 LE strings (Windows native encoding for Japanese)
            utf16_strings = []
            try:
                utf16_pattern = rb'(?:[\x20-\x7e]\x00|[\x00-\xff][\x30-\x9f]){3,50}'
                utf16_matches = re.findall(utf16_pattern, data)

                for match in utf16_matches:
                    try:
                        if len(match) % 2 != 0:
                            match = match[:-1]
                        decoded = match.decode('utf-16-le', errors='ignore').strip()
                        if decoded and re.search(r'[ぁ-んァ-ヶー一-龯]', decoded):
                            decoded = re.sub(r'[\x00-\x1f]', '', decoded).strip()
                            if len(decoded) >= 3 and len(decoded) <= 100:
                                if not re.search(r'[^\w\sぁ-んァ-ヶー一-龯・～〜\-]', decoded[:20]):
                                    utf16_strings.append(decoded)
                    except:
                        pass
            except Exception as e:
                logger.debug(f"UTF-16 extraction error: {e}")

            # Extract Shift-JIS strings
            shiftjis_strings = []
            try:
                sjis_matches = re.findall(rb'[\x81-\x9f\xe0-\xef][\x40-\x7e\x80-\xfc]{2,50}', data)
                for match in sjis_matches:
                    try:
                        decoded = match.decode('shift-jis', errors='ignore').strip()
                        if decoded and re.search(r'[ぁ-んァ-ヶー一-龯]', decoded):
                            if len(decoded) >= 2 and len(decoded) <= 100:
                                shiftjis_strings.append(decoded)
                    except:
                        pass
            except Exception as e:
                logger.debug(f"Shift-JIS extraction error: {e}")

            # Combine and deduplicate
            seen = set()
            for s in utf16_strings + shiftjis_strings:
                s = s.strip()
                if s and s not in seen and len(s) >= 3:
                    seen.add(s)
                    useful_strings.append(s)

            useful_strings = useful_strings[:30]

            if useful_strings:
                logger.info(f"Extracted {len(useful_strings)} Japanese strings from exe")

        except Exception as e:
            logger.error(f"Failed to extract strings from exe: {e}")

        return useful_strings

    def _get_exe_title(self, folder_path: str, contents: Dict) -> Optional[str]:
        """Extract game title from exe using multiple methods"""
        exe_title = None

        # Method 1: Config files (most reliable)
        logger.info("Trying to extract game title from config files...")
        exe_title = self._extract_game_title_from_config(folder_path)
        if exe_title:
            logger.info(f"✓ Found title from config: '{exe_title}'")
            return exe_title

        # Method 2: PE version info
        if contents.get('executables'):
            exe_path = os.path.join(folder_path, contents['executables'][0])
            logger.info(f"Trying PE version info from: {exe_path}")

            version_info = self._extract_exe_version_info(exe_path)
            if version_info:
                for key in ['ProductName', 'FileDescription', 'InternalName']:
                    if key in version_info:
                        candidate = version_info[key].strip()
                        if candidate.lower() not in ['game', 'game.exe', 'rpg_rt', 'rpgvxace', 'application', 'game_exe', 'nwjs', 'nw']:
                            exe_title = candidate
                            logger.info(f"✓ Found title from PE info ({key}): '{exe_title}'")
                            return exe_title

            # Method 3: String extraction
            logger.info("Trying string extraction from exe...")
            exe_strings = self._extract_exe_strings(exe_path)
            if exe_strings:
                # Take first Japanese string as potential title
                for s in exe_strings[:5]:
                    if re.search(r'[ぁ-んァ-ヶー一-龯]', s) and len(s) >= 3:
                        # Filter out common non-title strings
                        if not any(x in s.lower() for x in ['error', 'warning', 'failed', 'cannot', 'ツクール', 'rpg maker']):
                            exe_title = s
                            logger.info(f"✓ Found title from exe strings: '{exe_title}'")
                            return exe_title

        return None

    def _build_search_terms(self, folder_name: str, exe_title: Optional[str]) -> List[str]:
        """Build list of search terms to try"""
        search_terms = []

        # Clean folder name
        cleaned_folder = re.sub(r'\s*[\[\(]?(ver|v|version)[\s\d\.]+.*$', '', folder_name, flags=re.IGNORECASE)
        cleaned_folder = re.sub(r'\s*[\[\(].*?[\]\)]', '', cleaned_folder)
        cleaned_folder = re.sub(r'_+', ' ', cleaned_folder)
        cleaned_folder = re.sub(r'\s*製品版.*$', '', cleaned_folder)
        cleaned_folder = cleaned_folder.strip()

        # Extract Japanese from folder name
        japanese_from_folder = None
        japanese_match = re.search(r'[ぁ-んァ-ヶー一-龯]+[ぁ-んァ-ヶー一-龯\s・～〜\-]*', folder_name)
        if japanese_match:
            japanese_from_folder = japanese_match.group(0).strip()
            # Clean trial/version suffixes
            japanese_from_folder = re.sub(r'(体験版|Trial|Demo|デモ版|demo|trial|ver\.?[\d\.]+|v[\d\.]+).*$', '', japanese_from_folder, flags=re.IGNORECASE).strip()

        # Priority order for search terms
        if exe_title:
            # Clean exe title
            exe_title_clean = re.sub(r'(体験版|Trial|Demo|デモ版|demo|trial|ver\.?[\d\.]+|v[\d\.]+).*$', '', exe_title, flags=re.IGNORECASE).strip()
            if exe_title_clean:
                search_terms.append(exe_title_clean)
                search_terms.append(exe_title_clean.replace(' ', ''))
            search_terms.append(exe_title)
            search_terms.append(exe_title.replace(' ', ''))

        if japanese_from_folder:
            search_terms.append(japanese_from_folder)
            search_terms.append(japanese_from_folder.replace(' ', ''))

        search_terms.append(cleaned_folder)
        search_terms.append(folder_name)

        # Remove duplicates while preserving order
        seen = set()
        unique_terms = []
        for term in search_terms:
            if term and term not in seen and len(term) >= 2:
                seen.add(term)
                unique_terms.append(term)

        return unique_terms

    def _extract_version_from_folder_name(self, folder_name: str, release_date: Optional[str] = None) -> Optional[str]:
        """Extract version number from folder name"""
        patterns = [
            (r'(ver?\.?\s*\d{4}-\d{2}-\d{2})', 'date_version'),
            (r'(ver?\.?\s*\d+\.?\d*\.?\d*[a-z]?)', 'normal_version'),
            (r'_[vV](\d+\.?\d*\.?\d*[a-z]?)', 'underscore_version'),
        ]

        for pattern, version_type in patterns:
            match = re.search(pattern, folder_name, re.IGNORECASE)
            if match:
                version = match.group(0).strip('[]() _')

                if version_type == 'date_version':
                    date_match = re.search(r'(\d{4})-(\d{2})-(\d{2})', version)
                    if date_match:
                        year, month, day = date_match.groups()
                        formatted_date = f"{year[-2:]}{month}{day}"
                        if release_date and formatted_date == release_date:
                            continue
                        version = f"Ver.{year}-{month}-{day}"
                        return version

                if version_type in ['normal_version', 'underscore_version']:
                    version_digits = re.sub(r'[^0-9]', '', version)
                    if len(version_digits) == 6 and version_digits.isdigit():
                        if release_date and version_digits == release_date:
                            continue
                    return version

        return None

    def _clean_game_name(self, game_name: str, release_date: Optional[str] = None) -> str:
        """Clean game name by removing trailing dates and version markers"""
        cleaned = game_name

        if release_date:
            cleaned = re.sub(rf'\s*[\[\(]?{release_date}[\]\)]?\s*$', '', cleaned)
            cleaned = re.sub(rf'\s+{release_date}\s*$', '', cleaned)

        cleaned = re.sub(r'\s*[\[\(]?\d{6}[\]\)]?\s*$', '', cleaned)
        cleaned = re.sub(r'\s*[\[\(](ver?\.?\s*[\d\.\-]+[a-z]?)[\]\)]\s*$', '', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'\s*[\[\(]\d{4}-\d{2}-\d{2}[\]\)]\s*$', '', cleaned)
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()

        return cleaned

    def _move_to_non_dlsite_folder(self, folder_path: str) -> bool:
        """Move folders to NONDLSITEGAME directory"""
        folder_name = os.path.basename(folder_path)
        parent_dir = os.path.dirname(folder_path)
        non_dlsite_dir = os.path.join(parent_dir, "NONDLSITEGAME")

        try:
            if not os.path.exists(non_dlsite_dir):
                os.makedirs(non_dlsite_dir)
                logger.info(f"Created NONDLSITEGAME directory")

            destination = os.path.join(non_dlsite_dir, folder_name)

            if os.path.exists(destination):
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                destination = os.path.join(non_dlsite_dir, f"{folder_name}_{timestamp}")

            import shutil
            shutil.move(folder_path, destination)

            logger.info(f"✓ Moved to NONDLSITEGAME: {folder_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to move {folder_name}: {e}")
            return False

    def run(self):
        """Main execution loop"""
        logger.info(f"Starting game folder analysis in: {self.parent_folder}")

        logger.info("Starting rename viewer...")
        self._start_viewer()

        folders = self._get_folders()
        logger.info(f"Found {len(folders)} folders to process")

        try:
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
        finally:
            # Clean up browser
            logger.info("Closing browser...")
            self.searcher.close()

        self._print_summary()
        self._write_renamed_log()
        self._save_results()

        logger.info("\nProcessing complete!")
        logger.info("Press Ctrl+C to exit")

    def _get_folders(self) -> List[str]:
        """Get all folders in parent directory"""
        folders = []
        try:
            for item in os.listdir(self.parent_folder):
                item_path = os.path.join(self.parent_folder, item)
                if os.path.isdir(item_path):
                    if item not in {'.', '..', '__pycache__', 'DLsite', 'Sample', 'NONDLSITEGAME'}:
                        folders.append(item_path)
        except Exception as e:
            logger.error(f"Error reading parent folder: {e}")

        return sorted(folders)

    def _process_folder(self, folder_path: str):
        """Process a single folder"""
        folder_name = os.path.basename(folder_path)

        # Step 1: Get folder contents
        logger.info("Step 1: Analyzing folder contents...")
        contents = self._get_folder_contents(folder_path)

        if not contents['all_files']:
            logger.warning("No files found in folder")
            self.results['skipped'].append({
                'folder': folder_name,
                'reason': 'Empty folder'
            })
            self._save_results()
            return

        # Step 2: Check for RJ code in folder name
        logger.info("Step 2: Checking for RJ code in folder name...")
        rj_number = self._extract_rj_from_folder_name(folder_name)

        if rj_number:
            logger.info(f"✓ Found RJ code in folder name: {rj_number}")
        else:
            # Step 3: Extract exe title
            logger.info("Step 3: Extracting game title from exe...")
            exe_title = self._get_exe_title(folder_path, contents)

            # Step 4: Build search terms and search DDG
            logger.info("Step 4: Searching DuckDuckGo...")
            search_terms = self._build_search_terms(folder_name, exe_title)
            logger.info(f"Search terms: {search_terms[:5]}")

            rj_number = self.searcher.search_with_variations(search_terms)

        if not rj_number:
            logger.warning("Could not find RJ number - moving to NONDLSITEGAME")
            if self._move_to_non_dlsite_folder(folder_path):
                self.results['moved_non_dlsite'].append({
                    'folder': folder_name,
                    'reason': 'No RJ number found via DDG search'
                })
            else:
                self.results['errors'].append({
                    'folder': folder_name,
                    'error': 'Failed to move to NONDLSITEGAME'
                })
            self._save_results()
            return

        # Step 5: Get metadata from DLsite
        logger.info(f"Step 5: Fetching DLsite metadata for {rj_number}...")
        metadata = self.scraper.scrape_metadata(rj_number)

        if not metadata or not metadata.get('game_name'):
            logger.warning("Could not fetch metadata - moving to NONDLSITEGAME")
            if self._move_to_non_dlsite_folder(folder_path):
                self.results['moved_non_dlsite'].append({
                    'folder': folder_name,
                    'reason': f'Could not fetch metadata for {rj_number}'
                })
            else:
                self.results['errors'].append({
                    'folder': folder_name,
                    'error': 'Failed to move to NONDLSITEGAME'
                })
            self._save_results()
            return

        # Step 6: Rename folder
        logger.info("Step 6: Renaming folder...")
        game_name = metadata['game_name']
        author = metadata.get('author')
        release_date = metadata.get('release_date')

        success = self._rename_folder(
            folder_path,
            rj_number,
            game_name,
            author,
            release_date,
            self._extract_version_from_folder_name(folder_name, release_date)
        )

        if success:
            logger.info(f"✓ Successfully renamed")
        else:
            logger.error("✗ Rename failed")

    def _rename_folder(self, folder_path: str, rj_number: str, game_name: str,
                      author: Optional[str], release_date: Optional[str], version: Optional[str] = None) -> bool:
        """Rename the folder to standardized format"""
        folder_name = os.path.basename(folder_path)
        date_str = release_date if release_date else datetime.now().strftime('%y%m%d')

        # Clean names
        safe_name = re.sub(r'[<>:"/\\|?*]', '', game_name).strip()
        safe_name = self._clean_game_name(safe_name, date_str)

        # Build new name
        if author:
            safe_author = re.sub(r'[<>:"/\\|?*]', '', author).strip()
            new_name = f"[{date_str}][{rj_number}][{safe_author}]{safe_name}"
        else:
            new_name = f"[{date_str}][{rj_number}]{safe_name}"

        if version:
            new_name += f" {version}"

        # Skip if already correct
        if folder_name == new_name:
            logger.info("Folder already in correct format")
            self.results['skipped'].append({
                'folder': folder_name,
                'reason': 'Already in correct format'
            })
            self._save_results()
            return True

        new_path = os.path.join(os.path.dirname(folder_path), new_name)

        if os.path.exists(new_path):
            new_name = f"{new_name}_{datetime.now().strftime('%H%M%S')}"
            new_path = os.path.join(os.path.dirname(folder_path), new_name)

        try:
            os.rename(folder_path, new_path)

            self.results['renamed'].append({
                'original': folder_name,
                'new_name': new_name,
                'rj_number': rj_number,
                'game_name': game_name,
                'author': author,
                'release_date': release_date,
                'version': version
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

    def _write_renamed_log(self):
        """Write a log file with renamed games"""
        log_path = os.path.join(self.parent_folder, "renamed_games.txt")

        try:
            with open(log_path, 'w', encoding='utf-8') as f:
                f.write("# Renamed Games Log\n")
                f.write("# Format: Original; New Name; DLsite Link\n\n")

                for item in self.results['renamed']:
                    original = item['original']
                    new_name = item['new_name']
                    rj_number = item['rj_number']
                    dlsite_link = f"https://www.dlsite.com/maniax/work/=/product_id/{rj_number}.html"
                    f.write(f"{original}; {new_name}; {dlsite_link}\n")

            logger.info(f"Renamed games log written to: {log_path}")
        except Exception as e:
            logger.error(f"Failed to write renamed log: {e}")

    def _print_summary(self):
        """Print summary"""
        print("\n" + "="*60)
        print("RENAMING SUMMARY")
        print("="*60)

        print(f"\n✓ Renamed: {len(self.results['renamed'])}")
        for item in self.results['renamed']:
            print(f"  {item['original']}")
            print(f"    → {item['new_name']}")

        print(f"\n→ Moved to NONDLSITEGAME: {len(self.results['moved_non_dlsite'])}")

        if self.results['errors']:
            print(f"\n✗ Errors: {len(self.results['errors'])}")
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


def main():
    """Entry point"""
    parser = argparse.ArgumentParser(
        description='DLsite Game Folder Renamer (DDG+EXE Version) - No LLM required',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python game_renamer_DDGEXE.py
  python game_renamer_DDGEXE.py "E:\\同人\\RPG"
        '''
    )
    parser.add_argument(
        'parent_folder',
        type=str,
        nargs='?',
        help='Path to the parent folder containing game folders'
    )

    args = parser.parse_args()

    if args.parent_folder:
        parent_folder = args.parent_folder
    else:
        print("="*60)
        print("DLsite Game Folder Renamer - DDG+EXE Version")
        print("(No LLM required)")
        print("="*60)
        parent_folder = input("\nEnter the path to the folder containing game folders: ").strip()
        parent_folder = parent_folder.strip('"').strip("'")

    if not parent_folder:
        print("Error: No path provided")
        sys.exit(1)

    if not os.path.exists(parent_folder):
        print(f"Error: Directory '{parent_folder}' does not exist")
        sys.exit(1)

    if not os.path.isdir(parent_folder):
        print(f"Error: '{parent_folder}' is not a directory")
        sys.exit(1)

    setup_logging(parent_folder)

    logger.info("="*60)
    logger.info("DLsite Game Folder Renamer - DDG+EXE Version")
    logger.info("="*60)
    logger.info(f"Processing directory: {parent_folder}")

    try:
        renamer = GameRenamer(parent_folder)
        renamer.run()

        logger.info("\nViewer running at http://127.0.0.1:5000")
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
