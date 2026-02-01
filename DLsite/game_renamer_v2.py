#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DLsite Game Folder Renamer v2
Multi-stage LLM workflow for accurate game identification and renaming
Format: [YYMMDD][RJ########][Author]Game Name
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
from typing import Optional, Dict, List
from dataclasses import dataclass, field
from enum import Enum
import logging
import argparse

os.environ['TWOCAPTCHA_API_KEY'] = 'e74edcd8a9885786506b213be5f0880f'

# Force UTF-8 encoding for console output to handle Japanese characters
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Logger will be configured in main() after we know the processing directory
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
    try:
        from selenium_recaptcha_solver import RecaptchaSolver
        RECAPTCHA_SOLVER_AVAILABLE = True
    except ImportError:
        RECAPTCHA_SOLVER_AVAILABLE = False
    try:
        from twocaptcha import TwoCaptcha
        TWOCAPTCHA_AVAILABLE = True
    except ImportError:
        TWOCAPTCHA_AVAILABLE = False
except ImportError as e:
    logger.error(f"Required packages not installed. Install with: pip install requests selenium webdriver-manager selenium-stealth selenium-recaptcha-solver 2captcha-python")
    logger.error(f"Import error: {e}")
    sys.exit(1)


# Verification system data structures
class VerificationSource(Enum):
    """Sources used for game verification"""
    REGEX_FOLDER_NAME = "regex_folder_name"
    LLM_FILE_ANALYSIS = "llm_file_analysis"
    GOOGLE_SEARCH = "google_search"


@dataclass
class VerificationResult:
    """Result from multi-stage verification process"""
    is_dlsite: bool
    confidence: str  # 'high', 'medium', 'low'
    rj_number: Optional[str] = None
    game_name: Optional[str] = None
    author: Optional[str] = None
    sources: List[VerificationSource] = field(default_factory=list)
    reasoning: str = ""


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

    def query(self, prompt: str, temperature: float = 0.3, max_tokens: int = 300) -> Optional[str]:
        """Query the LLM with a prompt"""
        try:
            payload = {
                "model": "local-model",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "max_tokens": max_tokens
            }

            response = requests.post(self.api_url, json=payload, timeout=120)
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
            'rj_related': []
        }

        try:
            for root, dirs, files in os.walk(folder_path):
                depth = root.replace(folder_path, '').count(os.sep)
                if depth > 3:  # Increased depth to find files in nested folders
                    continue

                for file in files:
                    file_lower = file.lower()
                    rel_path = os.path.relpath(os.path.join(root, file), folder_path)

                    contents['all_files'].append(rel_path)

                    # Categorize files
                    if file_lower.endswith(('.exe', '.bat', '.cmd')):
                        contents['executables'].append(rel_path)

                    if file_lower.endswith(('.txt', '.md', '.readme')):
                        contents['text_files'].append(rel_path)

                    if any(x in file_lower for x in ['readme', 'お読み', '説明', 'manual', 'info']):
                        contents['readme_files'].append(rel_path)

                    if 'rj' in file_lower or 'dlsite' in file_lower:
                        contents['rj_related'].append(rel_path)

        except Exception as e:
            logger.error(f"Error reading folder {folder_path}: {e}")

        return contents

    def identify_useful_files(self, folder_name: str, contents: Dict) -> Dict:
        """Stage 1: LLM identifies which files contain useful game information"""

        # If there are very few files, just use them all
        if len(contents['all_files']) <= 3:
            useful = contents['text_files'] + contents['readme_files'] + contents['executables'][:1]
            if useful:
                logger.info(f"Few files detected, using all available: {useful}")
                return {
                    "useful_files": useful,
                    "reason": "Limited files available, using all"
                }

        # If no readme or text files, we'll rely heavily on search verification
        if not contents['readme_files'] and not contents['text_files']:
            logger.info("No readme or text files found - will rely on search verification")
            return {
                "useful_files": contents['executables'][:1] if contents['executables'] else [],
                "reason": "No text files available, minimal local information"
            }

        prompt = f"""Select files with game title/author/RJ number info.

Folder: {folder_name}
Executables: {', '.join(contents['executables'][:5]) if contents['executables'] else 'None'}
Text files: {', '.join(contents['text_files'][:8]) if contents['text_files'] else 'None'}
RJ-related: {', '.join(contents['rj_related'][:3]) if contents['rj_related'] else 'None'}

Priority: readme.txt > RJ files > text files
DO NOT select .exe files (binary).

OUTPUT JSON ONLY:
{{"useful_files": ["readme.txt"], "reason": "brief"}}"""

        logger.info("="*60)
        logger.info("STAGE 1: LLM IDENTIFYING USEFUL FILES")
        logger.info("="*60)
        logger.info(f"Prompt sent to LLM:\n{prompt}")

        response = self.llm.query(prompt, temperature=0.3, max_tokens=800)

        logger.info(f"\nLLM RAW RESPONSE:\n{response}")
        logger.info("="*60)

        if response:
            try:
                # Extract JSON from response
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group())
                    logger.info(f"PARSED JSON: {result}")
                    return result
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse LLM response: {response}")

        # Fallback: return readme and text files ONLY (no executables)
        fallback = {
            "useful_files": (contents['readme_files'] + contents['rj_related'] + contents['text_files'])[:5],
            "reason": "Fallback selection"
        }
        logger.info(f"Using fallback: {fallback}")
        return fallback

    def read_file_content(self, folder_path: str, file_path: str, max_chars: int = 1000) -> str:
        """Read content from a text file with automatic encoding detection"""
        try:
            full_path = os.path.join(folder_path, file_path)

            # Try common Japanese encodings in order
            encodings = ['utf-8', 'shift-jis', 'cp932', 'euc-jp', 'iso-2022-jp']

            for encoding in encodings:
                try:
                    with open(full_path, 'r', encoding=encoding) as f:
                        content = f.read(max_chars)
                        # Test if content looks reasonable (no too many special chars)
                        if content and len([c for c in content[:100] if ord(c) < 128 or ord(c) > 127]) > 0:
                            logger.debug(f"Successfully read {file_path} with {encoding}")
                            return content
                except (UnicodeDecodeError, UnicodeError):
                    continue

            # Last resort: read with utf-8 and ignore errors
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(max_chars)
                logger.warning(f"Read {file_path} with UTF-8 ignoring errors")
                return content

        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            return ""


class GameIdentifier:
    """Identifies game information using LLM"""

    def __init__(self, llm: LMStudioClient):
        self.llm = llm

    def identify_game(self, folder_name: str, useful_files: List[str],
                     file_contents: Dict[str, str]) -> Optional[Dict]:
        """Stage 2: LLM identifies game from folder name and file contents

        Also pre-extracts Japanese titles from standard 『』 brackets in readme files
        """

        # PRE-PROCESSING: Extract Japanese title from readme files
        # Japanese titles are usually marked with 『』 brackets
        # BUT we must filter out false positives like file references and tool names
        japanese_title_from_readme = None

        # Words/patterns that indicate this is NOT a game title
        false_positive_patterns = [
            r'\.txt',           # File references like 『02 素材提供者様.txt』
            r'\.exe',           # Exe references
            r'ツクール',        # RPG Maker references
            r'RPG\s*Maker',     # RPG Maker in English
            r'素材',            # "Material" references
            r'提供者',          # "Provider" references
            r'^[\d\s]+$',       # Just numbers
            r'^\d+\s',          # Starts with numbers (like file numbering)
        ]

        for filename, content in file_contents.items():
            if any(keyword in filename.lower() for keyword in ['readme', 'read me', '__readme']):
                # Look for Japanese title in 『』 brackets - find ALL matches and filter
                matches = re.findall(r'『([^』]+)』', content)
                for title_text in matches:
                    title_text = title_text.strip()

                    # Skip if matches any false positive pattern
                    is_false_positive = False
                    for fp_pattern in false_positive_patterns:
                        if re.search(fp_pattern, title_text, re.IGNORECASE):
                            logger.debug(f"Skipping false positive 『』 match: '{title_text}'")
                            is_false_positive = True
                            break

                    if is_false_positive:
                        continue

                    # Must contain actual Japanese characters AND be reasonable length
                    japanese_match = re.search(r'([ぁ-んァ-ヶー一-龯]{2,}[ぁ-んァ-ヶー一-龯\s・～〜\-]*)', title_text)
                    if japanese_match and len(japanese_match.group(1).strip()) >= 3:
                        japanese_title_from_readme = japanese_match.group(1).strip()
                        logger.info(f"Pre-extracted Japanese title from readme 『』: '{japanese_title_from_readme}'")
                        break

                if japanese_title_from_readme:
                    break

        # Build context - ONLY include text files, NOT binary executables
        context = f"Folder name: {folder_name}\n\n"

        for file, content in file_contents.items():
            # Skip binary files (exe, dll, etc.) - they just confuse the LLM
            if file.lower().endswith(('.exe', '.dll', '.pak', '.info')):
                continue
            if content:
                # Skip content that looks like binary garbage
                if 'This program cannot be run in DOS mode' in content or content.startswith('MZ'):
                    continue
                context += f"=== {file} ===\n{content[:600]}\n\n"

        prompt = f"""Extract game info from this DLsite game folder. Output JSON only.

{context}

RULES:
1. The folder name often contains or at least contains parts of the ACTUAL game title
2. game_name = core title only (no dates, versions, language tags)
3. rj_number = RJ followed by 6-8 digits, or null
4. author = circle/サークル name, or null
5. Look for ◆サークル or circle name in readme
6. MOST IMPORTANT: The exe runnable's title. That usually contains the game title

OUTPUT FORMAT (JSON only, no explanation):
{{"is_dlsite_game": true, "game_name": "title", "rj_number": "RJ123456", "author": "circle"}}"""

        logger.info("="*60)
        logger.info("STAGE 2: LLM IDENTIFYING GAME INFO")
        logger.info("="*60)
        logger.info(f"Prompt sent to LLM:\n{prompt}")

        response = self.llm.query(prompt, temperature=0.3, max_tokens=1000)

        logger.info(f"\nLLM RAW RESPONSE:\n{response}")
        logger.info("="*60)

        if response:
            try:
                # Extract JSON from response (may be after <think> tags)
                json_match = re.search(r'\{[^}]*"is_dlsite_game"[^}]*\}', response, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group())
                    logger.info(f"LLM identified: {result}")

                    # Clean the game name to remove dates/versions/language tags
                    if result.get('game_name'):
                        game_name = result['game_name']
                        # Remove language tags
                        game_name = re.sub(r'【[^】]+版】', '', game_name)
                        # Remove dates in brackets or parentheses
                        game_name = re.sub(r'[\[\(]\d{4}-\d{2}-\d{2}[\]\)]', '', game_name)
                        game_name = re.sub(r'[\[\(]\d{6}[\]\)]', '', game_name)
                        # Remove version info in parentheses
                        game_name = re.sub(r'\s*[\[\(](ver?\.?[\s\d\.\-]+)[\]\)]\s*', ' ', game_name, flags=re.IGNORECASE)
                        # Clean up
                        game_name = re.sub(r'\s+', ' ', game_name).strip()
                        result['game_name'] = game_name

                    # Enhance with pre-extracted Japanese title if LLM didn't find one
                    if japanese_title_from_readme:
                        llm_game_name = result.get('game_name', '')
                        # If LLM only found English title but we have Japanese, use Japanese
                        if llm_game_name and not re.search(r'[ぁ-んァ-ヶー一-龯]', llm_game_name):
                            logger.info(f"Enhancing LLM result with Japanese title: '{japanese_title_from_readme}'")
                            result['game_name'] = japanese_title_from_readme
                        elif not llm_game_name or llm_game_name == "game name here":
                            logger.info(f"LLM failed to extract game name, using pre-extracted: '{japanese_title_from_readme}'")
                            result['game_name'] = japanese_title_from_readme

                    return result
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse LLM response")

        # Fallback: if LLM completely failed, DON'T use pre-extracted title blindly
        # (it may be wrong like "ツクール" or "素材提供者様")
        # Instead, return minimal info and let search verification use folder name
        logger.warning("LLM failed to extract game info - will rely on folder name for search")
        return {
            'is_dlsite_game': True,  # Assume it is, let search verify
            'game_name': None,  # Don't guess - let search use folder name
            'rj_number': None,
            'author': None
        }


class DLsiteSearcher:
    """Searches for game on DLsite directly and via DuckDuckGo"""

    def __init__(self, llm: LMStudioClient):
        self.llm = llm
        self.session = requests.Session()
        self._setup_proxy()

    def _setup_proxy(self):
        """Set up Windows system proxy"""
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
                logger.info(f"Using proxy: {proxy_server}")
        except:
            pass

    def search_google_dlsite(self, game_name: str, rj_number: Optional[str] = None) -> str:
        """Search Google for DLsite page"""

        if rj_number:
            # Direct DLsite URL if we have RJ number
            return f"https://www.dlsite.com/maniax/work/=/product_id/{rj_number}.html"

        # Search query
        query = f"{game_name} dlsite"
        search_url = f"https://www.dlsite.com/maniax/fsr/=/language/jp/sex_category%5B0%5D/male/keyword/{quote(query)}"

        logger.info(f"Search URL: {search_url}")
        return search_url

    def _cleanup_driver(self, driver: Optional[webdriver.Chrome], chrome_pid: Optional[int] = None):
        """
        Robustly cleanup Selenium WebDriver and associated Chrome processes.
        """
        if not driver:
            return

        # Step 1: Try normal quit
        try:
            driver.quit()
            logger.debug("Driver quit() succeeded")
        except Exception as e:
            logger.debug(f"Driver quit() failed: {e}")

        # Step 2: Kill by PID if we tracked it
        if chrome_pid:
            try:
                import subprocess
                subprocess.run(
                    ['taskkill', '/F', '/T', '/PID', str(chrome_pid)],
                    capture_output=True,
                    timeout=5
                )
                logger.debug(f"Killed Chrome process tree (PID: {chrome_pid})")
            except Exception as e:
                logger.debug(f"Failed to kill Chrome by PID: {e}")

        # Step 3: Small delay to let processes terminate
        time.sleep(0.5)

    def _build_chrome_options(self, headless: bool, profile_dir: Optional[str] = None, profile_name: Optional[str] = None) -> Options:
        """Build Chrome options with common settings."""
        chrome_options = Options()

        if profile_dir:
            chrome_options.add_argument(f'--user-data-dir={profile_dir}')
            if profile_name:
                chrome_options.add_argument(f'--profile-directory={profile_name}')

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

        # Additional stealth options
        chrome_options.add_argument('--disable-infobars')
        chrome_options.add_argument('--start-maximized')
        chrome_options.add_argument('--window-size=1920,1080')

        # Use system proxy if available
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

    def _create_driver(self, chrome_options: Options) -> tuple[Optional[webdriver.Chrome], Optional[int]]:
        """Create a Chrome WebDriver with the given options. Returns (driver, chrome_pid)."""
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)

        chrome_pid = None
        try:
            chrome_pid = driver.service.process.pid
            logger.debug(f"ChromeDriver PID: {chrome_pid}")
        except:
            pass

        # Apply selenium-stealth if available
        if STEALTH_AVAILABLE:
            stealth(driver,
                languages=["en-US", "en"],
                vendor="Google Inc.",
                platform="Win32",
                webgl_vendor="Intel Inc.",
                renderer="Intel Iris OpenGL Engine",
                fix_hairline=True,
            )
            logger.info("Applied selenium-stealth to driver")

        return driver, chrome_pid

    def _init_selenium_driver(self, headless: bool = False) -> tuple[Optional[webdriver.Chrome], Optional[int]]:
        """
        Initialize Selenium Chrome WebDriver.
        Tries the user's Chrome profile first for cookies/history,
        then falls back to a separate Selenium profile if that fails.
        Returns tuple of (driver, chrome_pid) for proper cleanup.
        """
        local_app_data = os.environ.get('LOCALAPPDATA', '') if sys.platform == 'win32' else ''

        # Strategy 1: Use a separate persistent Selenium profile (avoids Chrome profile lock issues)
        selenium_profile = os.path.join(local_app_data, 'Google', 'Chrome Selenium') if sys.platform == 'win32' else os.path.join(os.path.expanduser('~'), '.chrome-selenium')
        try:
            logger.info(f"Trying Selenium profile: {selenium_profile}")
            opts = self._build_chrome_options(headless, selenium_profile, 'Default')
            driver, pid = self._create_driver(opts)
            logger.info("Successfully initialized with Selenium profile")
            return driver, pid
        except Exception as e:
            logger.warning(f"Selenium profile failed: {e}")

        # Strategy 2: No profile at all (clean session)
        try:
            logger.info("Trying with no profile (clean session)")
            opts = self._build_chrome_options(headless)
            driver, pid = self._create_driver(opts)
            logger.info("Successfully initialized with clean session")
            return driver, pid
        except Exception as e:
            logger.error(f"All Selenium initialization strategies failed: {e}")
            return None, None

    def _solve_recaptcha(self, driver: webdriver.Chrome) -> bool:
        """
        Attempt to solve reCAPTCHA automatically using selenium-recaptcha-solver.
        Uses the audio challenge approach with speech recognition.
        Returns True if solved successfully.
        """
        try:
            solver = RecaptchaSolver(driver=driver)

            # Find the reCAPTCHA iframe
            recaptcha_iframe = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.XPATH, '//iframe[contains(@src, "recaptcha") and contains(@title, "reCAPTCHA")]'))
            )

            logger.info("Found reCAPTCHA iframe, attempting automatic solve...")
            solver.click_recaptcha_v2(iframe=recaptcha_iframe)

            # Wait briefly and check if CAPTCHA is gone
            time.sleep(3)
            html = driver.page_source
            if 'captcha' not in html.lower() and 'unusual traffic' not in html.lower():
                logger.info("reCAPTCHA solved automatically")
                return True

            logger.warning("Automatic reCAPTCHA solve did not clear the page")
            return False

        except Exception as e:
            logger.warning(f"Automatic reCAPTCHA solve failed: {e}")
            return False

    def _solve_recaptcha_2captcha(self, driver: webdriver.Chrome) -> bool:
        """
        Attempt to solve reCAPTCHA using 2Captcha API service.
        Requires TWOCAPTCHA_API_KEY environment variable.
        Returns True if solved successfully.
        """
        api_key = os.environ.get('TWOCAPTCHA_API_KEY', '')
        if not api_key:
            logger.debug("No TWOCAPTCHA_API_KEY env var set, skipping 2Captcha")
            return False

        try:
            solver = TwoCaptcha(api_key)

            # Extract the reCAPTCHA sitekey from the page
            html = driver.page_source
            sitekey = None

            # Method 1: data-sitekey attribute (most common)
            sitekey_match = re.search(r'data-sitekey="([^"]+)"', html)
            if sitekey_match:
                sitekey = sitekey_match.group(1)
                logger.debug(f"Found sitekey via data-sitekey: {sitekey[:20]}...")

            # Method 2: In iframe src with k= parameter
            if not sitekey:
                sitekey_match = re.search(r'recaptcha[^"]*[?&]k=([A-Za-z0-9_-]{40})', html)
                if sitekey_match:
                    sitekey = sitekey_match.group(1)
                    logger.debug(f"Found sitekey via iframe k=: {sitekey[:20]}...")

            # Method 3: In grecaptcha.render() call
            if not sitekey:
                sitekey_match = re.search(r"grecaptcha\.render\([^)]*['\"]sitekey['\"]:\s*['\"]([^'\"]+)['\"]", html)
                if sitekey_match:
                    sitekey = sitekey_match.group(1)
                    logger.debug(f"Found sitekey via grecaptcha.render: {sitekey[:20]}...")

            # Method 4: Google's specific format in anchor URL
            if not sitekey:
                sitekey_match = re.search(r'anchor\?.*?k=([A-Za-z0-9_-]{40})', html)
                if sitekey_match:
                    sitekey = sitekey_match.group(1)
                    logger.debug(f"Found sitekey via anchor URL: {sitekey[:20]}...")

            if not sitekey:
                logger.warning("Could not find reCAPTCHA sitekey on page")
                return False
            page_url = driver.current_url

            logger.info(f"Sending reCAPTCHA to 2Captcha (sitekey: {sitekey[:12]}...)")
            result = solver.recaptcha(sitekey=sitekey, url=page_url)

            token = result.get('code', '') if isinstance(result, dict) else str(result)
            if not token:
                logger.warning("2Captcha returned empty token")
                return False

            # Inject the token into the page and trigger callback
            # Google reCAPTCHA requires: 1) setting textarea value 2) calling callback
            driver.execute_script(f'''
                // Find all g-recaptcha-response textareas (may be multiple or in iframes)
                var responseElements = document.querySelectorAll('[id="g-recaptcha-response"], [name="g-recaptcha-response"]');
                responseElements.forEach(function(el) {{
                    el.value = "{token}";
                    el.innerHTML = "{token}";
                    el.style.display = "block";
                }});

                // Try to find and call Google's callback function
                // Method 1: Look for callback in grecaptcha config
                if (typeof ___grecaptcha_cfg !== 'undefined') {{
                    var clients = ___grecaptcha_cfg.clients;
                    for (var key in clients) {{
                        var client = clients[key];
                        // Navigate through the nested structure to find callback
                        if (client && client.W && client.W.W && typeof client.W.W.callback === 'function') {{
                            client.W.W.callback("{token}");
                            console.log("2Captcha: Called callback via ___grecaptcha_cfg");
                        }}
                    }}
                }}

                // Method 2: Check for data-callback attribute on reCAPTCHA div
                var recaptchaDiv = document.querySelector('.g-recaptcha[data-callback]');
                if (recaptchaDiv) {{
                    var callbackName = recaptchaDiv.getAttribute('data-callback');
                    if (callbackName && typeof window[callbackName] === 'function') {{
                        window[callbackName]("{token}");
                        console.log("2Captcha: Called callback via data-callback");
                    }}
                }}
            ''')

            # Give callback time to process
            time.sleep(2)

            # Try to submit the form as fallback
            try:
                driver.execute_script('''
                    var forms = document.getElementsByTagName("form");
                    if (forms.length > 0) forms[0].submit();
                ''')
            except Exception:
                pass

            time.sleep(3)
            html = driver.page_source
            if 'captcha' not in html.lower() and 'unusual traffic' not in html.lower():
                logger.info("reCAPTCHA solved via 2Captcha")
                return True

            logger.warning("2Captcha token injected but page not cleared")
            return False

        except Exception as e:
            logger.warning(f"2Captcha solve failed: {e}")
            return False

    def _search_google_for_dlsite(self, search_query: str) -> Optional[str]:
        """
        Use Google to search for DLsite games via Selenium with user's Chrome profile.
        Using the existing profile avoids reCAPTCHA since it has cookies/history.
        """
        logger.info(f"Google search: '{search_query}'")

        driver = None
        chrome_pid = None
        try:
            # Use non-headless mode with user profile to avoid detection
            driver, chrome_pid = self._init_selenium_driver(headless=False)
            if not driver:
                logger.warning("Selenium driver initialization failed")
                return None

            # Google search URL
            google_url = f"https://www.google.com/search?q={quote(search_query + ' site:dlsite.com')}"
            logger.info(f"Selenium navigating to: {google_url}")

            driver.get(google_url)

            # Wait for page load with random delay to appear human
            import random
            time.sleep(random.uniform(2.0, 4.0))

            html = driver.page_source

            # Check for CAPTCHA
            if 'captcha' in html.lower() or 'unusual traffic' in html.lower():
                logger.warning("Google reCAPTCHA detected")

                # Try automated solving first
                captcha_solved = False
                if RECAPTCHA_SOLVER_AVAILABLE:
                    captcha_solved = self._solve_recaptcha(driver)

                # Try 2Captcha API service as second attempt
                if not captcha_solved and TWOCAPTCHA_AVAILABLE:
                    captcha_solved = self._solve_recaptcha_2captcha(driver)

                # Fall back to manual solve with shorter timeout
                if not captcha_solved:
                    logger.warning("Waiting for manual CAPTCHA solve (up to 30 seconds)...")
                    for i in range(30):
                        time.sleep(1)
                        html = driver.page_source
                        if 'captcha' not in html.lower() and 'unusual traffic' not in html.lower():
                            logger.info("CAPTCHA solved manually, continuing...")
                            captcha_solved = True
                            break
                    else:
                        logger.warning("CAPTCHA not solved in time")
                        return None

                # Re-read page after CAPTCHA solved
                if captcha_solved:
                    time.sleep(1)
                    html = driver.page_source

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
                    logger.info(f"✓ Google found RJ code: {rj_number}")
                    return rj_number.upper()

            logger.info("Google found no RJ codes")
            return None

        except Exception as e:
            logger.error(f"Google search failed: {e}")
            return None

        finally:
            # Use robust cleanup to prevent orphaned processes
            self._cleanup_driver(driver, chrome_pid)

    def _title_similarity(self, folder_name: str, found_title: str) -> float:
        """Calculate similarity between folder name and found title (0.0 to 1.0)"""
        # Clean both strings for comparison
        def clean_for_compare(s):
            s = s.lower()
            # Remove common noise
            s = re.sub(r'[\[\]\(\)\{\}【】『』「」\-_~～・]', ' ', s)
            s = re.sub(r'\s+', ' ', s).strip()
            # Remove version info
            s = re.sub(r'\s*(ver|v|version)[\s\d\.]+.*$', '', s, flags=re.IGNORECASE)
            s = re.sub(r'\s*製品版.*$', '', s)
            return s

        folder_clean = clean_for_compare(folder_name)
        title_clean = clean_for_compare(found_title)

        # Check for exact substring match
        if folder_clean in title_clean or title_clean in folder_clean:
            return 1.0

        # Check for significant word overlap
        folder_words = set(folder_clean.split())
        title_words = set(title_clean.split())

        if not folder_words or not title_words:
            return 0.0

        # Remove very short/common words
        folder_words = {w for w in folder_words if len(w) >= 2}
        title_words = {w for w in title_words if len(w) >= 2}

        if not folder_words:
            return 0.0

        # Calculate Jaccard similarity
        intersection = len(folder_words & title_words)
        union = len(folder_words | title_words)

        if union == 0:
            return 0.0

        return intersection / union

    def verify_is_dlsite_game(self, folder_name: str, game_name: Optional[str] = None) -> Dict:
        """
        Multi-tier search to verify if this is a DLsite game:
        1. DLsite direct search with multiple variations (aggressive)
        2. Google search via Selenium with user's Chrome profile (fallback)
        """
        import random

        logger.info("="*60)
        logger.info("MULTI-TIER SEARCH VERIFICATION")
        logger.info("="*60)

        search_query = game_name if game_name else folder_name

        # Remove version numbers and common suffixes for better search
        cleaned_query = re.sub(r'\s*[\[\(]?(ver|v|version)[\s\d\.]+.*$', '', search_query, flags=re.IGNORECASE)
        cleaned_query = re.sub(r'\s*[\[\(].*?[\]\)]', '', cleaned_query)  # Remove bracketed text
        cleaned_query = re.sub(r'_+', ' ', cleaned_query)  # Replace underscores with spaces
        cleaned_query = re.sub(r'\s*製品版.*$', '', cleaned_query)  # Remove "製品版" suffix
        cleaned_query = cleaned_query.strip()

        # Extract potential Japanese title from BOTH game_name AND folder_name
        japanese_title = None
        japanese_title_clean = None

        # Check both game_name and folder_name for Japanese characters
        # But exclude common noise words that aren't game titles
        noise_words = {'製品版', '体験版', '完全版', '通常版', '限定版', 'デモ版'}

        sources_to_check = [s for s in [game_name, folder_name] if s]
        for source in sources_to_check:
            # Look for Japanese characters (Hiragana, Katakana, Kanji)
            japanese_match = re.search(r'[ぁ-んァ-ヶー一-龯]+[ぁ-んァ-ヶー一-龯\s・～〜\-]*', source)
            if japanese_match:
                potential_title = japanese_match.group(0).strip()

                # Skip if it's just a noise word
                if potential_title.rstrip('-') in noise_words:
                    logger.debug(f"Skipping noise word: '{potential_title}'")
                    continue

                japanese_title = potential_title
                logger.info(f"Extracted Japanese title from '{source[:30]}...': '{japanese_title}'")

                # Strip common trial/demo/version suffixes from Japanese title for better searching
                japanese_title_clean = re.sub(r'(体験版|Trial|Demo|デモ版|demo|trial|ver\.?[\d\.]+|v[\d\.]+).*$', '', japanese_title, flags=re.IGNORECASE).strip()
                if japanese_title_clean != japanese_title and japanese_title_clean:
                    logger.info(f"Cleaned Japanese title (removed trial/version suffix): '{japanese_title_clean}'")
                break  # Use first found Japanese title

        # TIER 1: DLsite direct search with multiple variations
        logger.info(f"Tier 1: DLsite direct search with variations")

        # Build search variations - prioritize Japanese title if available
        search_variations = []

        if japanese_title:
            # Add cleaned version first (without trial/version suffixes)
            if japanese_title_clean:
                search_variations.append(japanese_title_clean)  # Cleaned Japanese (highest priority)
                search_variations.append(japanese_title_clean.replace(' ', ''))  # Cleaned without spaces

            search_variations.append(japanese_title)  # Original Japanese title
            search_variations.append(japanese_title.replace(' ', ''))  # Japanese without spaces

        search_variations.extend([
            cleaned_query,  # Cleaned English/folder name
            cleaned_query.lower(),  # Lowercase
            search_query,  # Original query
        ])

        # Remove duplicates while preserving order
        seen = set()
        search_variations = [x for x in search_variations if x and not (x in seen or seen.add(x)) and len(x) >= 2]

        for i, query in enumerate(search_variations, 1):
            logger.info(f"  Variation {i}/{len(search_variations)}: '{query}'")

            try:
                dlsite_search_url = f"https://www.dlsite.com/maniax/fsr/=/language/jp/sex_category%5B0%5D/male/keyword/{quote(query)}"

                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept-Language': 'ja,en-US;q=0.9,en;q=0.8'
                }
                response = self.session.get(dlsite_search_url, headers=headers, timeout=20)

                if response.status_code == 200:
                    html = response.text

                    # Extract RJ numbers AND their titles from search results
                    # Pattern: <a href="...product_id/RJxxxxxx.html">Title</a>
                    # More reliable: look for work list items with both RJ and title
                    work_pattern = r'<a[^>]*href="[^"]*product_id/(RJ\d{6,8})\.html"[^>]*>([^<]+)</a>'
                    work_matches = re.findall(work_pattern, html)

                    if work_matches:
                        # Check each result for title match with folder name
                        best_match = None
                        best_similarity = 0.0

                        for rj_num, title in work_matches[:10]:  # Check top 10 results
                            title = title.strip()
                            similarity = self._title_similarity(folder_name, title)

                            logger.debug(f"  Checking {rj_num}: '{title}' (similarity: {similarity:.2f})")

                            if similarity > best_similarity:
                                best_similarity = similarity
                                best_match = (rj_num, title)

                            # If we find a very good match, stop early
                            if similarity >= 0.7:
                                break

                        # Accept if similarity is good enough
                        if best_match and best_similarity >= 0.3:
                            rj_number, matched_title = best_match
                            logger.info(f"✓ DLsite found matching game: {rj_number} '{matched_title}' (similarity: {best_similarity:.2f})")
                            return {
                                'is_dlsite': True,
                                'rj_number': rj_number,
                                'confidence': 'high' if best_similarity >= 0.5 else 'medium',
                                'source': 'dlsite_search',
                                'matched_title': matched_title
                            }
                        else:
                            # Found results but none match folder name
                            if work_matches:
                                logger.info(f"  Found {len(work_matches)} results but none match folder name (best: {best_similarity:.2f})")

                # Random delay between variations to appear human
                if i < len(search_variations):
                    delay = random.uniform(0.8, 2.0)
                    logger.debug(f"Waiting {delay:.1f}s before next variation...")
                    time.sleep(delay)

            except Exception as e:
                logger.debug(f"DLsite search variation {i} failed: {e}")

        logger.info("DLsite direct search exhausted")

        # TIER 2: Google search via Selenium with user's Chrome profile
        logger.info(f"Tier 2: Google search for '{cleaned_query}'")
        rj_from_google = self._search_google_for_dlsite(cleaned_query)

        if rj_from_google:
            logger.info(f"✓ Google found game: {rj_from_google}")
            return {
                'is_dlsite': True,
                'rj_number': rj_from_google,
                'confidence': 'high',
                'source': 'google_search'
            }

        # No results found
        logger.info(f"All search methods failed for '{search_query}'")
        return {
            'is_dlsite': False,
            'confidence': 'medium',
            'reasoning': 'No results found in DLsite search'
        }


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

    def scrape_metadata(self, url: str) -> Optional[Dict]:
        """Extract metadata from DLsite product page"""

        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }

            response = self.session.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            html = response.text

            # Extract RJ number from URL
            rj_match = re.search(r'(RJ\d{6,8})', url)
            rj_number = rj_match.group(1) if rj_match else None

            # Extract game name from og:title meta tag (cleaner than <title>)
            og_title_match = re.search(r'<meta\s+property="og:title"\s+content="([^"]+)"', html)
            if og_title_match:
                game_name = og_title_match.group(1)
                # Remove " | DLsite" suffix
                game_name = re.sub(r'\s*\|\s*DLsite.*$', '', game_name)
                # Remove circle name in brackets at the end
                game_name = re.sub(r'\s*\[[^\]]+\]\s*$', '', game_name)
                # Remove language tags like 【简体中文版】【繁體中文版】
                game_name = re.sub(r'【[^】]+版】', '', game_name)
                game_name = game_name.strip()
            else:
                # Fallback to title tag
                title_match = re.search(r'<title>([^<]+)</title>', html)
                game_name = title_match.group(1).strip() if title_match else None
                if game_name:
                    game_name = re.sub(r'\s*[\|｜].*$', '', game_name).strip()
                    # Remove language tags
                    game_name = re.sub(r'【[^】]+版】', '', game_name).strip()

            # Extract circle name from table
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

            # Extract release date from table (format: YYYY年MM月DD日)
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

        # Initialize components
        self.llm = LMStudioClient()
        if not self.llm.check_connection():
            raise RuntimeError("LMStudio not running on localhost:1234")

        self.folder_analyzer = FolderAnalyzer(self.llm)
        self.game_identifier = GameIdentifier(self.llm)
        self.searcher = DLsiteSearcher(self.llm)  # Fix: pass LLM instance
        # Set debug directory for the searcher to save debug files in processing location
        self.searcher.debug_dir = parent_folder
        self.scraper = DLsiteScraper()

        self.results = {
            'renamed': [],
            'skipped': [],
            'moved_non_dlsite': [],  # Track all non-renamed games moved to NONDLSITEGAME
            'errors': []
        }

        # Initialize results file
        self._save_results()

    def _start_viewer(self):
        """Start the rename viewer as a separate process (survives main script exit)"""
        try:
            viewer_path = os.path.join(os.path.dirname(__file__), 'rename_viewer.py')

            if not os.path.exists(viewer_path):
                logger.warning("rename_viewer.py not found, skipping viewer auto-start")
                return

            # Spawn viewer as a completely independent process
            # Uses CREATE_NEW_PROCESS_GROUP and DETACHED_PROCESS so it survives parent exit
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
                # Unix: use start_new_session to detach
                subprocess.Popen(
                    [sys.executable, viewer_path, self.parent_folder, '--port', '5000'],
                    start_new_session=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL
                )

            logger.info("Started rename viewer at http://127.0.0.1:5000 (independent process)")

            # Open browser after short delay
            time.sleep(1)
            webbrowser.open('http://127.0.0.1:5000')

        except Exception as e:
            logger.warning(f"Could not start viewer: {e}")
            logger.warning("You can start it manually with: python rename_viewer.py")

    def _extract_rj_from_folder_name(self, folder_name: str) -> Optional[str]:
        """Extract RJ code from folder name using regex"""
        patterns = [
            r'\b(RJ\d{8})\b',  # 8 digits (most specific)
            r'\b(RJ\d{6})\b',  # 6 digits (older format)
            r'(RJ\d{6,8})',    # Flexible 6-8 digits
        ]

        for pattern in patterns:
            match = re.search(pattern, folder_name, re.IGNORECASE)
            if match:
                rj_code = match.group(1).upper()
                logger.info(f"Regex extracted RJ code from folder name: {rj_code}")
                return rj_code

        return None

    def _extract_version_from_folder_name(self, folder_name: str, release_date: Optional[str] = None) -> Optional[str]:
        """Extract version number from folder name if present, avoiding date duplicates"""
        # Common version patterns - prioritize specific version markers
        patterns = [
            (r'(ver?\.?\s*\d{4}-\d{2}-\d{2})', 'date_version'),  # Ver.2023-05-29
            (r'(ver?\.?\s*\d+\.?\d*\.?\d*[a-z]?)', 'normal_version'),  # ver1.0, v1.00, Ver1.2.3a
            (r'_[vV](\d+\.?\d*\.?\d*[a-z]?)', 'underscore_version'),  # _v1.00, _V1.0
        ]

        for pattern, version_type in patterns:
            match = re.search(pattern, folder_name, re.IGNORECASE)
            if match:
                version = match.group(0).strip('[]() _')

                # Handle date-based versions (Ver.2023-05-29)
                if version_type == 'date_version':
                    # Extract just the date part and format it
                    date_match = re.search(r'(\d{4})-(\d{2})-(\d{2})', version)
                    if date_match:
                        year, month, day = date_match.groups()
                        formatted_date = f"{year[-2:]}{month}{day}"

                        # Check if this date matches the release date - if so, skip it
                        if release_date and formatted_date == release_date:
                            logger.info(f"Skipping version date {version} - matches release date")
                            continue

                        # Keep the version format but clean it up
                        version = f"Ver.{year}-{month}-{day}"
                        logger.info(f"Extracted date-based version: {version}")
                        return version

                # For normal versions, check if it's not just a date disguised as version
                # Avoid extracting bare dates like "240803" or "[230317]"
                if version_type in ['normal_version', 'underscore_version']:
                    # Check if version is just 6 digits (YYMMDD format date)
                    version_digits = re.sub(r'[^0-9]', '', version)
                    if len(version_digits) == 6 and version_digits.isdigit():
                        # This looks like a date (YYMMDD), check if it matches release date
                        if release_date and version_digits == release_date:
                            logger.info(f"Skipping version {version} - it's the release date")
                            continue

                    logger.info(f"Extracted version from folder name: {version}")
                    return version

        return None

    def _clean_game_name(self, game_name: str, release_date: Optional[str] = None) -> str:
        """Clean game name by removing trailing dates and version markers that would be duplicates"""
        cleaned = game_name

        # Remove trailing date in [YYMMDD] or YYMMDD format
        if release_date:
            # Remove exact match of release date at the end
            cleaned = re.sub(rf'\s*[\[\(]?{release_date}[\]\)]?\s*$', '', cleaned)
            cleaned = re.sub(rf'\s+{release_date}\s*$', '', cleaned)

        # Remove trailing date patterns (6-digit dates at the end)
        cleaned = re.sub(r'\s*[\[\(]?\d{6}[\]\)]?\s*$', '', cleaned)

        # ONLY remove version info if it's in brackets/parentheses at the end
        # This prevents removing versions that might be part of the actual title
        cleaned = re.sub(r'\s*[\[\(](ver?\.?\s*[\d\.\-]+[a-z]?)[\]\)]\s*$', '', cleaned, flags=re.IGNORECASE)

        # Remove trailing dates in YYYY-MM-DD format (in brackets/parentheses)
        cleaned = re.sub(r'\s*[\[\(]\d{4}-\d{2}-\d{2}[\]\)]\s*$', '', cleaned)

        # Clean up multiple spaces
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()

        if cleaned != game_name:
            logger.info(f"Cleaned game name: '{game_name}' -> '{cleaned}'")

        return cleaned

    def _is_generic_name(self, folder_name: str) -> bool:
        """Check if folder name is too generic for reliable searching"""
        # Remove version info and special chars for analysis
        cleaned = re.sub(r'\s*[\[\(]?(ver|v|version)[\s\d\.]+.*$', '', folder_name, flags=re.IGNORECASE)
        cleaned = re.sub(r'[_\-\[\]\(\)]', ' ', cleaned).strip()

        # Generic if:
        # - Single word and very short (<=6 chars)
        # - Common generic words
        # - All numbers
        words = cleaned.split()

        if len(words) == 1:
            word = words[0].lower()
            # Single short word
            if len(word) <= 6:
                logger.info(f"Generic name detected: single short word '{word}'")
                return True
            # Common generic words
            generic_words = {'game', 'test', 'demo', 'sample', 'rpg', 'action', 'adventure',
                           'sakura', 'fantasy', 'quest', 'story', 'battle', 'dungeon'}
            if word in generic_words:
                logger.info(f"Generic name detected: common word '{word}'")
                return True

        # All numbers
        if cleaned.replace(' ', '').isdigit():
            logger.info(f"Generic name detected: all numbers '{cleaned}'")
            return True

        return False

    def _extract_exe_strings(self, exe_path: str, min_len: int = 4) -> List[str]:
        """Extract ASCII strings from executable file (window titles, app names, etc.)"""
        try:
            with open(exe_path, "rb") as f:
                data = f.read()

            # Extract ASCII printable strings
            pattern = rb"[ -~]{%d,}" % min_len
            strings = [s.decode("ascii", errors="ignore") for s in re.findall(pattern, data)]

            # Filter for potentially useful strings (window titles, app names)
            useful_strings = []
            keywords = ['title', 'window', 'app', 'game', 'name', 'caption',
                       'product', 'description', 'copyright', 'company']

            for s in strings:
                s_lower = s.lower()
                # Look for strings that might contain game info
                if any(kw in s_lower for kw in keywords):
                    useful_strings.append(s)
                # Also include strings with Japanese characters nearby (might be game title)
                elif len(s) > 10 and len(s) < 100:  # Reasonable length for a title
                    useful_strings.append(s)

            # Limit to avoid too much data
            return useful_strings[:50]

        except Exception as e:
            logger.error(f"Failed to extract strings from exe: {e}")
            return []

    def _analyze_exe_strings_with_llm(self, exe_strings: List[str], folder_name: str) -> Optional[str]:
        """Ask LLM to analyze exe strings and suggest better search terms"""
        if not exe_strings:
            return None

        # Filter strings to only include potentially useful ones
        filtered_strings = []
        for s in exe_strings[:50]:
            s = s.strip()
            # Skip very short or very long strings
            if len(s) < 4 or len(s) > 200:
                continue
            # Skip obvious garbage
            if s.startswith(('MZ', 'PE', 'L!', '!L', 'DOS', '.text', '.rdata', '.data')):
                continue
            if 'cannot be run' in s.lower() or 'dos mode' in s.lower():
                continue
            filtered_strings.append(s)

        if not filtered_strings:
            return None

        prompt = f"""Find the game window title from these exe strings.

Folder: {folder_name}

Strings found:
{chr(10).join(filtered_strings[:20])}

Look for: window title, ProductName, game name in Japanese/English.
Ignore: paths, errors, "Game", "RPG Maker", "tkool".

OUTPUT ONLY THE GAME TITLE (one line, no explanation).
If not found, output: NONE"""

        response = self.llm.query(prompt, temperature=0.1, max_tokens=100)

        if response:
            # Clean up response
            title = response.strip().strip('"\'')
            # Reject if it's the generic response or too short/long
            if title and title.upper() != "NONE" and len(title) > 2 and len(title) < 100:
                # Reject if it's just generic words
                if title.lower() not in ['game', 'rpg maker', 'maker', 'window', 'title', 'application']:
                    logger.info(f"LLM extracted title from exe strings: '{title}'")
                    return title

        return None

    def _verify_is_dlsite_game(self, folder_path: str, folder_name: str,
                               game_info: Optional[Dict], contents: Dict) -> VerificationResult:
        """
        Multi-stage verification pipeline with progressive fallbacks
        Returns comprehensive verification result with confidence levels
        """

        verification_sources = []
        rj_number = None
        is_dlsite = False
        confidence = 'low'
        reasoning = []

        # STAGE 1: Regex extraction from folder name (fast, high confidence)
        logger.info("="*60)
        logger.info("Verification Stage 1: Regex RJ extraction from folder name")
        regex_rj = self._extract_rj_from_folder_name(folder_name)

        if regex_rj:
            logger.info(f"✓ Found RJ code in folder name: {regex_rj}")
            rj_number = regex_rj
            is_dlsite = True
            confidence = 'high'
            verification_sources.append(VerificationSource.REGEX_FOLDER_NAME)
            reasoning.append(f"RJ code found in folder name: {regex_rj}")

        # STAGE 2: LLM file analysis results
        logger.info("Verification Stage 2: LLM file analysis")
        if game_info:
            llm_says_dlsite = game_info.get('is_dlsite_game', False)
            llm_rj = game_info.get('rj_number')

            if llm_says_dlsite:
                verification_sources.append(VerificationSource.LLM_FILE_ANALYSIS)
                reasoning.append("LLM identified as DLsite game from file contents")

                if llm_rj:
                    if not rj_number:
                        rj_number = llm_rj
                    elif rj_number != llm_rj:
                        logger.warning(f"RJ mismatch: folder={rj_number}, LLM={llm_rj}")
                        # Trust folder name over LLM

                is_dlsite = True
                if confidence == 'low':
                    confidence = 'medium'
            else:
                reasoning.append("LLM did not identify as DLsite game")

        # STAGE 2.5: EXE String Extraction for Generic Names
        # If folder name is too generic and we haven't found clear evidence yet,
        # extract strings from exe to find actual game title
        enhanced_search_term = None
        if self._is_generic_name(folder_name) and confidence == 'low':
            logger.info("Verification Stage 2.5: Generic name detected - extracting exe strings")

            if contents.get('executables'):
                exe_path = os.path.join(folder_path, contents['executables'][0])
                logger.info(f"Extracting strings from: {exe_path}")

                exe_strings = self._extract_exe_strings(exe_path)

                if exe_strings:
                    logger.info(f"Extracted {len(exe_strings)} strings from exe")
                    enhanced_search_term = self._analyze_exe_strings_with_llm(exe_strings, folder_name)

                    if enhanced_search_term:
                        logger.info(f"✓ Enhanced search term from exe: '{enhanced_search_term}'")
                        reasoning.append(f"Extracted game title from exe: {enhanced_search_term}")
                    else:
                        logger.warning("Could not extract useful title from exe strings")
                        reasoning.append("Generic name + no useful exe strings")
                else:
                    logger.warning("No strings extracted from exe")
            else:
                logger.warning("Generic name but no exe file found")
                reasoning.append("Generic name + no exe to analyze")

        # STAGE 3: Multi-tier search verification (only if uncertain OR contradictory)
        # Tier 1: DLsite direct search (most reliable)
        # Tier 2: DuckDuckGo fallback (if DLsite fails)
        # Run verification if:
        # - No RJ found yet, OR
        # - LLM says "not DLsite" but we want to verify, OR
        # - Confidence is still low/medium

        should_search_verify = (
            not is_dlsite or
            confidence in ['low', 'medium'] or
            (game_info and not game_info.get('is_dlsite_game'))
        )

        if should_search_verify:
            logger.info("Verification Stage 3: Multi-tier search verification")

            # Use enhanced search term if available, otherwise game name from LLM, otherwise folder name
            search_term = enhanced_search_term or (game_info.get('game_name') if game_info else None)
            search_result = self.searcher.verify_is_dlsite_game(folder_name, search_term)

            if search_result.get('is_dlsite'):
                verification_sources.append(VerificationSource.GOOGLE_SEARCH)  # Keep enum name for compatibility
                is_dlsite = True

                # Extract RJ from search if available
                search_rj = search_result.get('rj_number')
                if search_rj and not rj_number:
                    rj_number = search_rj
                    source = search_result.get('source', 'search')
                    logger.info(f"✓ Search found RJ code: {search_rj} (via {source})")

                # Upgrade confidence based on search result
                search_confidence = search_result.get('confidence', 'low')
                if search_confidence == 'high':
                    confidence = 'high'
                elif confidence == 'low' and search_confidence == 'medium':
                    confidence = 'medium'

                reasoning.append(f"Search confirmed game (confidence: {search_confidence}, source: {search_result.get('source', 'unknown')})")
            else:
                reasoning.append("Search did not find game")

        # FINAL DECISION MATRIX
        # High confidence: 2+ sources agree OR regex found RJ
        # Medium confidence: 1 strong source (LLM + search, or regex alone)
        # Low confidence: No clear evidence

        if len(verification_sources) >= 2:
            confidence = 'high'

        logger.info(f"Verification complete: is_dlsite={is_dlsite}, confidence={confidence}")
        logger.info(f"Sources: {[s.value for s in verification_sources]}")
        logger.info(f"Reasoning: {' | '.join(reasoning)}")
        logger.info("="*60)

        return VerificationResult(
            is_dlsite=is_dlsite,
            confidence=confidence,
            rj_number=rj_number,
            game_name=game_info.get('game_name') if game_info else None,
            author=game_info.get('author') if game_info else None,
            sources=verification_sources,
            reasoning=" | ".join(reasoning)
        )

    def _move_to_non_dlsite_folder(self, folder_path: str) -> bool:
        """
        Move confirmed non-DLsite folders to NONDLSITEGAME directory
        Creates the directory if it doesn't exist
        """

        folder_name = os.path.basename(folder_path)
        parent_dir = os.path.dirname(folder_path)

        # Create NONDLSITEGAME folder in parent directory
        non_dlsite_dir = os.path.join(parent_dir, "NONDLSITEGAME")

        try:
            if not os.path.exists(non_dlsite_dir):
                os.makedirs(non_dlsite_dir)
                logger.info(f"Created NONDLSITEGAME directory: {non_dlsite_dir}")

            # Move folder
            destination = os.path.join(non_dlsite_dir, folder_name)

            # Handle duplicates
            if os.path.exists(destination):
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                destination = os.path.join(non_dlsite_dir, f"{folder_name}_{timestamp}")

            import shutil
            shutil.move(folder_path, destination)

            logger.info(f"✓ Moved to NONDLSITEGAME: {folder_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to move {folder_name} to NONDLSITEGAME: {e}")
            return False



    def run(self):
        """Main execution loop"""
        logger.info(f"Starting game folder analysis in: {self.parent_folder}")

        # Start the viewer in background
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
                self._save_results()  # Save after each error

        self._print_summary()
        self._write_renamed_log()
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
                    # Skip system folders and NONDLSITEGAME folder
                    if item not in {'.', '..', '__pycache__', 'DLsite', 'Sample', 'NONDLSITEGAME'}:
                        folders.append(item_path)
        except Exception as e:
            logger.error(f"Error reading parent folder: {e}")

        return sorted(folders)

    def _process_folder(self, folder_path: str):
        """Process a single folder through the complete multi-stage workflow"""
        folder_name = os.path.basename(folder_path)

        # Step 1: Get folder contents
        logger.info("Step 1: Analyzing folder contents...")
        contents = self.folder_analyzer.get_folder_contents(folder_path)

        if not contents['all_files']:
            logger.warning("No files found in folder")
            self.results['skipped'].append({
                'folder': folder_name,
                'reason': 'Empty folder'
            })
            self._save_results()  # Save immediately for real-time updates
            return

        # Step 2: Identify useful files (LLM Stage 1)
        logger.info("Step 2: LLM identifying useful files...")
        useful_info = self.folder_analyzer.identify_useful_files(folder_name, contents)
        logger.info(f"Useful files: {useful_info.get('useful_files', [])}")

        # Step 3: Read contents of useful files
        logger.info("Step 3: Reading file contents...")
        file_contents = {}
        for file in useful_info.get('useful_files', [])[:5]:  # Limit to 5 files
            content = self.folder_analyzer.read_file_content(folder_path, file)
            if content:
                file_contents[file] = content

        # Step 4: Identify game (LLM Stage 2)
        logger.info("Step 4: LLM identifying game information...")
        game_info = self.game_identifier.identify_game(
            folder_name,
            useful_info.get('useful_files', []),
            file_contents
        )

        # === NEW: MULTI-STAGE VERIFICATION ===
        logger.info("Step 5: Multi-stage verification (Regex + LLM + Exe Strings + Search)...")
        verification = self._verify_is_dlsite_game(folder_path, folder_name, game_info, contents)

        logger.info(f"Verification result: is_dlsite={verification.is_dlsite}, "
                    f"confidence={verification.confidence}, "
                    f"sources={[s.value for s in verification.sources]}")
        logger.info(f"Reasoning: {verification.reasoning}")

        # Decision based on verification result
        if not verification.is_dlsite:
            # High confidence it's NOT a DLsite game -> move to NONDLSITEGAME
            if verification.confidence in ['high', 'medium']:
                logger.warning(f"Confirmed non-DLsite game (confidence: {verification.confidence})")

                if self._move_to_non_dlsite_folder(folder_path):
                    self.results['moved_non_dlsite'].append({
                        'folder': folder_name,
                        'reason': verification.reasoning,
                        'confidence': verification.confidence
                    })
                    self._save_results()  # Save immediately
                else:
                    self.results['errors'].append({
                        'folder': folder_name,
                        'error': 'Failed to move to NONDLSITEGAME'
                    })
                    self._save_results()  # Save immediately
            else:
                # Low confidence - also move to NONDLSITEGAME for review
                logger.warning(f"Uncertain if DLsite game (low confidence)")
                if self._move_to_non_dlsite_folder(folder_path):
                    self.results['moved_non_dlsite'].append({
                        'folder': folder_name,
                        'reason': f'Low confidence - {verification.reasoning}',
                        'confidence': verification.confidence
                    })
                    self._save_results()  # Save immediately
                else:
                    self.results['errors'].append({
                        'folder': folder_name,
                        'error': 'Failed to move to NONDLSITEGAME'
                    })
                    self._save_results()  # Save immediately
            return

        # It IS a DLsite game - proceed with renaming
        rj_number = verification.rj_number
        game_name = verification.game_name
        author = verification.author

        # Step 6: Get full metadata from DLsite if we have RJ number
        if rj_number:
            logger.info(f"Step 6: Fetching DLsite metadata for {rj_number}...")
            dlsite_url = f"https://www.dlsite.com/maniax/work/=/product_id/{rj_number}.html"
            metadata = self.scraper.scrape_metadata(dlsite_url)

            if metadata:
                # Use scraped metadata (more reliable)
                rj_number = metadata.get('rj_number') or rj_number
                game_name = metadata.get('game_name') or game_name
                author = metadata.get('author') or author
                release_date = metadata.get('release_date')
            else:
                release_date = None
        else:
            # No RJ number even after verification - this shouldn't happen often
            # Try searching by game name
            if game_name:
                logger.info(f"Step 6: Searching DLsite for '{game_name}'...")
                search_url = self.searcher.search_google_dlsite(game_name)
                metadata = self.scraper.scrape_metadata(search_url)

                if metadata and metadata.get('rj_number'):
                    rj_number = metadata['rj_number']
                    game_name = metadata.get('game_name') or game_name
                    author = metadata.get('author') or author
                    release_date = metadata.get('release_date')
                else:
                    logger.warning("Could not find RJ number even with search - moving to NONDLSITEGAME")

                    if self._move_to_non_dlsite_folder(folder_path):
                        self.results['moved_non_dlsite'].append({
                            'folder': folder_name,
                            'reason': 'DLsite game but no RJ number found',
                            'confidence': 'low'
                        })
                        self._save_results()  # Save immediately
                    else:
                        self.results['errors'].append({
                            'folder': folder_name,
                            'error': 'Failed to move to NONDLSITEGAME'
                        })
                        self._save_results()  # Save immediately
                    return
            else:
                logger.warning("No game name to search with - moving to NONDLSITEGAME")

                if self._move_to_non_dlsite_folder(folder_path):
                    self.results['moved_non_dlsite'].append({
                        'folder': folder_name,
                        'reason': 'No identifying info found'
                    })
                    self._save_results()  # Save immediately
                else:
                    self.results['errors'].append({
                        'folder': folder_name,
                        'error': 'Failed to move to NONDLSITEGAME'
                    })
                    self._save_results()  # Save immediately
                return

        # Verify we have minimum required info
        if not rj_number or not game_name:
            logger.warning("Insufficient metadata for renaming - moving to NONDLSITEGAME")

            if self._move_to_non_dlsite_folder(folder_path):
                self.results['moved_non_dlsite'].append({
                    'folder': folder_name,
                    'reason': f"Missing {'RJ number' if not rj_number else 'game name'}"
                })
                self._save_results()  # Save immediately
            else:
                self.results['errors'].append({
                    'folder': folder_name,
                    'error': 'Failed to move to NONDLSITEGAME'
                })
                self._save_results()  # Save immediately
            return

        # Build new name preview
        date_str = release_date if release_date else datetime.now().strftime('%y%m%d')

        # Clean game name to remove trailing dates/versions that would be duplicates
        cleaned_game_name = self._clean_game_name(game_name, date_str)

        new_preview = f"[{date_str}][{rj_number}]"
        if author:
            new_preview += f"[{author}]"
        new_preview += cleaned_game_name

        # Preserve version from original folder name if present
        version = self._extract_version_from_folder_name(folder_name, release_date)
        if version:
            new_preview += f" {version}"
            logger.info(f"Preserving version in renamed folder: {version}")

        # Skip if already in correct format
        if folder_name == new_preview:
            logger.info("Folder already in correct format, skipping")
            self.results['skipped'].append({
                'folder': folder_name,
                'reason': 'Already in correct format'
            })
            self._save_results()  # Save immediately
            return

        # Step 7: Rename folder
        logger.info("Step 7: Renaming folder...")
        success = self._rename_folder(
            folder_path,
            rj_number,
            game_name,
            author,
            release_date,
            version  # Pass version to rename method
        )

        if success:
            logger.info(f"✓ Successfully renamed with confidence: {verification.confidence}")
        else:
            logger.error("✗ Rename failed")

    def _verify_rename(self, old_name: str, game_name: str, rj_number: str, author: Optional[str], release_date: Optional[str] = None) -> bool:
        """Ask LLM to verify if the rename makes sense"""

        date_str = release_date if release_date else datetime.now().strftime('%y%m%d')
        new_name_preview = f"[{date_str}][{rj_number}]"
        if author:
            new_name_preview += f"[{author}]"
        new_name_preview += game_name

        prompt = f"""Does this rename make sense?

Original: {old_name}
New name: {new_name_preview}

Think about it, then answer "yes" or "no"."""

        logger.info("="*60)
        logger.info("STAGE 3: LLM VERIFICATION")
        logger.info("="*60)
        logger.info(f"Prompt sent to LLM:\n{prompt}")

        response = self.llm.query(prompt, temperature=0.1, max_tokens=500)

        logger.info(f"\nLLM RAW RESPONSE:\n{response}")
        logger.info("="*60)

        if response:
            is_approved = 'yes' in response.lower()
            logger.info(f"LLM DECISION: {'APPROVED' if is_approved else 'REJECTED'}")
            return is_approved

        return True  # Default to yes if LLM fails

    def _rename_folder(self, folder_path: str, rj_number: str, game_name: str,
                      author: Optional[str], release_date: Optional[str], version: Optional[str] = None) -> bool:
        """Rename the folder to standardized format"""

        folder_name = os.path.basename(folder_path)

        # Format date
        date_str = release_date if release_date else datetime.now().strftime('%y%m%d')

        # Clean names
        safe_name = re.sub(r'[<>:"/\\|?*]', '', game_name).strip()

        # Build new name
        if author:
            safe_author = re.sub(r'[<>:"/\\|?*]', '', author).strip()
            new_name = f"[{date_str}][{rj_number}][{safe_author}]{safe_name}"
        else:
            new_name = f"[{date_str}][{rj_number}]{safe_name}"

        # Append version if present in original folder name
        if version:
            new_name += f" {version}"
            logger.info(f"Appended version to new name: {version}")

        new_path = os.path.join(os.path.dirname(folder_path), new_name)

        # Avoid duplicates
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
                'version': version  # Track version in results
            })

            self._save_results()  # Save immediately for real-time updates

            return True

        except Exception as e:
            logger.error(f"Rename failed: {e}")
            self.results['errors'].append({
                'folder': folder_name,
                'error': f'Rename failed: {str(e)}'
            })
            self._save_results()  # Save immediately
            return False

    def _save_results(self):
        """Save results to JSON (called incrementally for real-time updates)"""
        output_file = os.path.join(self.parent_folder, 'rename_results.json')
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save results: {e}")

    def _write_renamed_log(self):
        """Write a simple log file with renamed games and their DLsite links"""
        log_path = os.path.join(self.parent_folder, "renamed_games.txt")

        try:
            with open(log_path, 'w', encoding='utf-8') as f:
                f.write("# Renamed Games Log\n")
                f.write("# Format: Original Folder; New Name; DLsite Link\n\n")

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

        # All non-renamed games in one folder
        print(f"\n→ Moved to NONDLSITEGAME (for review): {len(self.results['moved_non_dlsite'])}")

        if self.results['errors']:
            print(f"\n✗ Errors: {len(self.results['errors'])}")
            for item in self.results['errors']:
                print(f"  {item['folder']}: {item['error']}")

        print("\n" + "="*60)


def setup_logging(log_dir: str):
    """Set up logging to save logs in the processing directory"""
    log_file = os.path.join(log_dir, 'game_renamer.log')

    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    stream_handler = logging.StreamHandler(sys.stdout)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[file_handler, stream_handler],
        force=True  # Force reconfiguration
    )

    logger.info(f"Logging to: {log_file}")


def main():
    """Entry point"""

    # Parse command line arguments (optional)
    parser = argparse.ArgumentParser(
        description='DLsite Game Folder Renamer - Rename game folders to standardized format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python game_renamer_v2.py
  python game_renamer_v2.py "E:\\同人\\RPG"
        '''
    )
    parser.add_argument(
        'parent_folder',
        type=str,
        nargs='?',  # Make it optional
        help='Path to the parent folder containing game folders to rename'
    )

    args = parser.parse_args()

    # If no command-line argument provided, prompt for input
    if args.parent_folder:
        parent_folder = args.parent_folder
    else:
        print("="*60)
        print("DLsite Game Folder Renamer v2")
        print("="*60)
        parent_folder = input("\nEnter the path to the folder containing game folders: ").strip()
        # Remove quotes if user pasted path with quotes
        parent_folder = parent_folder.strip('"').strip("'")

    # Validate parent folder
    if not parent_folder:
        print("Error: No path provided")
        sys.exit(1)

    if not os.path.exists(parent_folder):
        print(f"Error: Directory '{parent_folder}' does not exist")
        sys.exit(1)

    if not os.path.isdir(parent_folder):
        print(f"Error: '{parent_folder}' is not a directory")
        sys.exit(1)

    # Set up logging to save in the processing directory
    setup_logging(parent_folder)

    logger.info("="*60)
    logger.info("DLsite Game Folder Renamer v2")
    logger.info("="*60)
    logger.info(f"Processing directory: {parent_folder}")

    try:
        renamer = GameRenamer(parent_folder)
        renamer.run()

        # Keep running to maintain the viewer
        logger.info("\nViewer is still running at http://127.0.0.1:5000")
        logger.info("You can review the results and reverse any renames")
        logger.info("Press Ctrl+C to exit")

        try:
            # Keep the main thread alive
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
