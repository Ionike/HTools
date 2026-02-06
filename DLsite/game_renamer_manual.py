#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DLsite Game Folder Renamer - Manual Input Version
For each folder, manually input a DLsite link or RJ code.
Enter 0 to skip.
Format: [YYMMDD][RJ########][Author]Game Name
"""

import os
import json
import re
import sys
from datetime import datetime
from typing import Optional, Dict, List

# Force UTF-8 encoding for console output to handle Japanese characters
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

try:
    import requests
except ImportError:
    print("Required package not installed. Install with: pip install requests")
    sys.exit(1)


class DLsiteScraper:
    """Scrapes metadata from DLsite pages"""

    def __init__(self):
        self.session = requests.Session()
        self._setup_proxy()

    def _setup_proxy(self):
        """Set up proxy from Windows settings"""
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

    def extract_rj_from_input(self, user_input: str) -> Optional[str]:
        """Extract RJ code from user input (URL or direct code)"""
        user_input = user_input.strip()

        # Direct RJ code input
        rj_match = re.search(r'(RJ\d{6,8})', user_input, re.IGNORECASE)
        if rj_match:
            return rj_match.group(1).upper()

        # URL patterns
        url_patterns = [
            r'dlsite\.com/[^/]+/work/[^/]+/product_id/(RJ\d{6,8})',
            r'dlsite\.com/[^/]+/product_id/(RJ\d{6,8})',
            r'product_id/(RJ\d{6,8})',
        ]

        for pattern in url_patterns:
            match = re.search(pattern, user_input, re.IGNORECASE)
            if match:
                return match.group(1).upper()

        return None

    def scrape_metadata(self, rj_number: str) -> Optional[Dict]:
        """Extract metadata from DLsite product page"""
        # Try maniax first, then home
        urls = [
            f"https://www.dlsite.com/maniax/work/=/product_id/{rj_number}.html",
            f"https://www.dlsite.com/home/work/=/product_id/{rj_number}.html",
        ]

        for url in urls:
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }

                response = self.session.get(url, headers=headers, timeout=15)
                if response.status_code == 404:
                    continue
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

                if not game_name:
                    continue

                # Extract circle name
                circle_patterns = [
                    r'<th>サークル名</th>\s*<td[^>]*>.*?<a[^>]*>([^<]+)</a>',
                    r'<th>サークル</th>\s*<td[^>]*>.*?<a[^>]*>([^<]+)</a>',
                    r'<span class="maker_name"[^>]*>.*?<a[^>]*>([^<]+)</a>',
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

                return {
                    'rj_number': rj_number,
                    'game_name': game_name,
                    'author': author,
                    'release_date': release_date,
                    'url': url
                }

            except Exception as e:
                continue

        return None


class ManualGameRenamer:
    """Manual renamer that prompts for DLsite links"""

    def __init__(self, parent_folder: str):
        self.parent_folder = parent_folder
        self.scraper = DLsiteScraper()
        self.results = {
            'renamed': [],
            'skipped': [],
            'errors': []
        }

    def _get_folders(self) -> List[str]:
        """Get all folders in parent directory"""
        folders = []
        skip_folders = {'.', '..', '__pycache__', 'DLsite', 'Sample', 'NONDLSITEGAME'}

        try:
            for item in os.listdir(self.parent_folder):
                item_path = os.path.join(self.parent_folder, item)
                if os.path.isdir(item_path) and item not in skip_folders:
                    folders.append(item_path)
        except Exception as e:
            print(f"Error reading parent folder: {e}")

        return sorted(folders)

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
                        return f"Ver.{year}-{month}-{day}"

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

    def _rename_folder(self, folder_path: str, rj_number: str, game_name: str,
                      author: Optional[str], release_date: Optional[str], version: Optional[str] = None) -> bool:
        """Rename the folder to standardized format"""
        folder_name = os.path.basename(folder_path)
        date_str = release_date if release_date else datetime.now().strftime('%y%m%d')

        # Clean names for filesystem
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
            print(f"  Already in correct format")
            self.results['skipped'].append({
                'folder': folder_name,
                'reason': 'Already in correct format'
            })
            return True

        new_path = os.path.join(os.path.dirname(folder_path), new_name)

        # Handle duplicate names
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
            return True

        except Exception as e:
            print(f"  Rename failed: {e}")
            self.results['errors'].append({
                'folder': folder_name,
                'error': f'Rename failed: {str(e)}'
            })
            return False

    def run(self):
        """Main execution loop"""
        print("=" * 60)
        print("DLsite Game Folder Renamer - Manual Input Version")
        print("=" * 60)
        print(f"Processing directory: {self.parent_folder}")
        print()
        print("For each folder, enter a DLsite link or RJ code.")
        print("Enter 0 to skip the folder.")
        print("=" * 60)

        folders = self._get_folders()
        print(f"\nFound {len(folders)} folders to process\n")

        for i, folder_path in enumerate(folders, 1):
            folder_name = os.path.basename(folder_path)

            print(f"\n{'─' * 60}")
            print(f"[{i}/{len(folders)}] {folder_name}")
            print(f"{'─' * 60}")

            user_input = input("DLsite link/RJ code (0 to skip): ").strip()

            if user_input == '0':
                print("  Skipped")
                self.results['skipped'].append({
                    'folder': folder_name,
                    'reason': 'User skipped'
                })
                continue

            if not user_input:
                print("  No input, skipping")
                self.results['skipped'].append({
                    'folder': folder_name,
                    'reason': 'No input'
                })
                continue

            # Extract RJ code
            rj_number = self.scraper.extract_rj_from_input(user_input)

            if not rj_number:
                print(f"  Could not extract RJ code from: {user_input}")
                self.results['errors'].append({
                    'folder': folder_name,
                    'error': f'Invalid input: {user_input}'
                })
                continue

            print(f"  Found RJ code: {rj_number}")
            print(f"  Fetching metadata...")

            # Get metadata
            metadata = self.scraper.scrape_metadata(rj_number)

            if not metadata or not metadata.get('game_name'):
                print(f"  Could not fetch metadata for {rj_number}")
                self.results['errors'].append({
                    'folder': folder_name,
                    'error': f'Could not fetch metadata for {rj_number}'
                })
                continue

            # Show metadata
            print(f"  Title: {metadata['game_name']}")
            print(f"  Author: {metadata.get('author', 'N/A')}")
            print(f"  Date: {metadata.get('release_date', 'N/A')}")

            # Rename
            version = self._extract_version_from_folder_name(folder_name, metadata.get('release_date'))
            success = self._rename_folder(
                folder_path,
                rj_number,
                metadata['game_name'],
                metadata.get('author'),
                metadata.get('release_date'),
                version
            )

            if success:
                print(f"  ✓ Renamed successfully")

        self._print_summary()
        self._save_results()

    def _print_summary(self):
        """Print summary"""
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)

        print(f"\n✓ Renamed: {len(self.results['renamed'])}")
        for item in self.results['renamed']:
            print(f"  {item['original']}")
            print(f"    → {item['new_name']}")

        print(f"\n⊘ Skipped: {len(self.results['skipped'])}")
        for item in self.results['skipped']:
            print(f"  {item['folder']}: {item['reason']}")

        if self.results['errors']:
            print(f"\n✗ Errors: {len(self.results['errors'])}")
            for item in self.results['errors']:
                print(f"  {item['folder']}: {item['error']}")

        print("\n" + "=" * 60)

    def _save_results(self):
        """Save results to JSON"""
        output_file = os.path.join(self.parent_folder, 'manual_rename_results.json')
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, ensure_ascii=False, indent=2)
            print(f"\nResults saved to: {output_file}")
        except Exception as e:
            print(f"Failed to save results: {e}")


def main():
    """Entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description='DLsite Game Folder Renamer - Manual Input Version',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python game_renamer_manual.py
  python game_renamer_manual.py "E:\\Games"
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
        print("=" * 60)
        print("DLsite Game Folder Renamer - Manual Input Version")
        print("=" * 60)
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

    try:
        renamer = ManualGameRenamer(parent_folder)
        renamer.run()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
