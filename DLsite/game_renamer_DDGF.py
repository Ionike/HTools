#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DLsite Game Folder Renamer - DDG + Folder Name Version
Simplest workflow: Folder name -> DuckDuckGo search -> DLsite metadata
No LLM, no exe extraction required.
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
except ImportError as e:
    logger.error(f"Required packages not installed. Install with: pip install requests")
    sys.exit(1)


class DDGSearcher:
    """Searches for game on DLsite via DuckDuckGo"""

    def __init__(self):
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

    def search_duckduckgo(self, search_query: str) -> Optional[str]:
        """
        Use DuckDuckGo HTML search to find DLsite games.
        Returns RJ number if found.
        """
        logger.info(f"DuckDuckGo search: '{search_query}'")

        try:
            ddg_url = f"https://html.duckduckgo.com/html/?q={quote(search_query + ' site:dlsite.com')}"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                'Accept-Language': 'ja,en-US;q=0.9,en;q=0.8'
            }

            response = self.session.get(ddg_url, headers=headers, timeout=20)

            if response.status_code != 200:
                logger.warning(f"DuckDuckGo returned status {response.status_code}")
                return None

            html = response.text

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
            return None

    def search_with_variations(self, search_terms: List[str]) -> Optional[str]:
        """
        Try multiple search variations to find the game.
        Returns RJ number if found.
        """
        import random

        # Remove duplicates while preserving order
        seen = set()
        unique_terms = [x for x in search_terms if x and not (x in seen or seen.add(x)) and len(x) >= 2]

        for i, term in enumerate(unique_terms, 1):
            logger.info(f"Search attempt {i}/{len(unique_terms)}: '{term}'")
            rj_number = self.search_duckduckgo(term)

            if rj_number:
                return rj_number

            # Small delay between searches
            if i < len(unique_terms):
                time.sleep(random.uniform(0.5, 1.5))

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

    def _build_search_terms_from_folder(self, folder_name: str) -> List[str]:
        """Build list of search terms from folder name only"""
        search_terms = []

        # Original folder name
        search_terms.append(folder_name)

        # Clean folder name - remove version info
        cleaned = re.sub(r'\s*[\[\(]?(ver|v|version)[\s\d\.]+.*$', '', folder_name, flags=re.IGNORECASE)
        cleaned = re.sub(r'\s*[\[\(].*?[\]\)]', '', cleaned)  # Remove bracketed text
        cleaned = re.sub(r'_+', ' ', cleaned)  # Replace underscores with spaces
        cleaned = re.sub(r'\s*製品版.*$', '', cleaned)  # Remove "製品版" suffix
        cleaned = re.sub(r'\s*体験版.*$', '', cleaned)  # Remove "体験版" suffix
        cleaned = cleaned.strip()

        if cleaned and cleaned != folder_name:
            search_terms.append(cleaned)

        # Extract Japanese text from folder name
        japanese_match = re.search(r'[ぁ-んァ-ヶー一-龯]+[ぁ-んァ-ヶー一-龯\s・～〜\-]*', folder_name)
        if japanese_match:
            japanese_title = japanese_match.group(0).strip()
            # Clean trial/version suffixes
            japanese_clean = re.sub(r'(体験版|Trial|Demo|デモ版|demo|trial|ver\.?[\d\.]+|v[\d\.]+).*$', '', japanese_title, flags=re.IGNORECASE).strip()

            if japanese_clean and len(japanese_clean) >= 2:
                search_terms.append(japanese_clean)
                # Also try without spaces
                no_spaces = japanese_clean.replace(' ', '')
                if no_spaces != japanese_clean:
                    search_terms.append(no_spaces)

            if japanese_title and japanese_title != japanese_clean:
                search_terms.append(japanese_title)

        # Lowercase version
        if cleaned:
            search_terms.append(cleaned.lower())

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

        # Step 1: Check for RJ code in folder name
        logger.info("Step 1: Checking for RJ code in folder name...")
        rj_number = self._extract_rj_from_folder_name(folder_name)

        if rj_number:
            logger.info(f"✓ Found RJ code in folder name: {rj_number}")
        else:
            # Step 2: Build search terms from folder name and search DDG
            logger.info("Step 2: Building search terms from folder name...")
            search_terms = self._build_search_terms_from_folder(folder_name)
            logger.info(f"Search terms: {search_terms}")

            logger.info("Step 3: Searching DuckDuckGo...")
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

        # Step 4: Get metadata from DLsite
        logger.info(f"Step 4: Fetching DLsite metadata for {rj_number}...")
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

        # Step 5: Rename folder
        logger.info("Step 5: Renaming folder...")
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
        description='DLsite Game Folder Renamer (DDG+Folder Version) - Simplest, no LLM/exe required',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python game_renamer_DDGF.py
  python game_renamer_DDGF.py "E:\\同人\\RPG"
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
        print("DLsite Game Folder Renamer - DDG+Folder Version")
        print("(Simplest version - no LLM, no exe extraction)")
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
    logger.info("DLsite Game Folder Renamer - DDG+Folder Version")
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
