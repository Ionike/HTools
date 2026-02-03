"""
Manually extract ComicInfo.xml from ExHentai gallery URL
Loops through gallery folders in a parent directory and prompts for URLs
"""

import re
import sys
from pathlib import Path
from xml.etree.ElementTree import Element, ElementTree
import requests

# Paths
COOKIE_FILE = Path(r"C:\VSCode\HTools\E-Hentai\cookie\cookie_exhentai.txt")

# Gallery link pattern
GALLERY_LINK_PATTERN = r'https://exhentai\.org/g/(\d+)/([a-f0-9]+)/?'


class ExHentaiFetcher:
    """Fetch gallery info from ExHentai"""

    def __init__(self, cookie_file_path):
        self.cookies = self._load_cookies(cookie_file_path)
        self.session = requests.Session()
        self.session.cookies.update(self.cookies)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def _load_cookies(self, cookie_file):
        cookies = {}
        try:
            with open(cookie_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split('\t')
                    if len(parts) >= 7:
                        cookies[parts[5]] = parts[6]
            print(f"[INFO] Loaded {len(cookies)} cookies")
        except Exception as e:
            print(f"[ERROR] Failed to load cookies: {e}")
        return cookies

    def fetch_gallery_info(self, gallery_url):
        """Fetch and extract gallery information"""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            print("[ERROR] BeautifulSoup not installed. Run: pip install beautifulsoup4")
            return None

        try:
            print(f"[INFO] Fetching: {gallery_url}")
            response = self.session.get(gallery_url, timeout=15)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            info = {
                'url': gallery_url,
                'source': 'exhentai',
                'title_english': '',
                'title_japanese': '',
                'artist': '',
                'group': '',
                'characters': '',
                'tags': '',
                'page_count': '',
                'rating': '',
                'parody': '',
                'language': ''
            }

            gn = soup.find(id='gn')
            if gn:
                info['title_english'] = gn.get_text().strip()

            gj = soup.find(id='gj')
            if gj:
                info['title_japanese'] = gj.get_text().strip()

            for td in soup.find_all('td', class_='gdt1'):
                label = td.get_text().strip()
                value_td = td.find_next('td', class_='gdt2')
                if not value_td:
                    continue

                if label == 'Length:':
                    match = re.search(r'(\d+)\s*pages?', value_td.get_text())
                    if match:
                        info['page_count'] = match.group(1)
                elif label == 'Language:':
                    info['language'] = value_td.get_text().strip()

            rating_label = soup.find(id='rating_label')
            if rating_label:
                match = re.search(r'[\d.]+', rating_label.get_text())
                if match:
                    info['rating'] = match.group(0)

            for row in soup.find_all('tr'):
                tds = row.find_all('td')
                if len(tds) >= 2:
                    tag_type = tds[0].get_text().strip().lower()
                    tags = [a.get_text() for a in tds[1].find_all('a')]

                    if tag_type == 'group:':
                        info['group'] = ', '.join(tags)
                    elif tag_type == 'artist:':
                        info['artist'] = ', '.join(tags)
                    elif tag_type == 'character:':
                        info['characters'] = ', '.join(tags)
                    elif tag_type == 'parody:':
                        info['parody'] = ', '.join(tags)
                    elif tag_type in ('female:', 'male:', 'mixed:', 'other:'):
                        if info['tags']:
                            info['tags'] += ', ' + ', '.join(tags)
                        else:
                            info['tags'] = ', '.join(tags)

            return info

        except Exception as e:
            print(f"[ERROR] Failed to fetch gallery: {e}")
            return None


class ComicInfoGenerator:
    """Generate ComicInfo.xml files"""

    @staticmethod
    def create(gallery_info, output_path):
        """Create ComicInfo.xml from gallery info"""
        root = Element('ComicInfo')
        root.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        root.set('xsi:noNamespaceSchemaLocation',
                'https://raw.githubusercontent.com/anansi-project/comicinfo/main/schema/v2.0/ComicInfo.xsd')

        field_map = [
            ('title_english', 'Series'),
            ('title_japanese', 'AlternateSeries'),
            ('artist', 'Penciller'),
            ('group', 'Writer'),
            ('characters', 'Characters'),
            ('parody', 'Teams'),
            ('tags', 'Genre'),
            ('page_count', 'PageCount'),
            ('rating', 'CommunityRating'),
            ('language', 'LanguageISO'),
            ('url', 'Web'),
        ]

        for info_key, xml_tag in field_map:
            value = gallery_info.get(info_key, '')
            if value:
                elem = Element(xml_tag)
                elem.text = str(value)
                root.append(elem)

        tree = ElementTree(root)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)
        return True


def validate_url(url):
    """Validate that URL matches ExHentai gallery pattern"""
    if re.match(GALLERY_LINK_PATTERN, url):
        return True
    if re.match(r'https://e-hentai\.org/g/(\d+)/([a-f0-9]+)/?', url):
        return True
    return False


def main():
    print("=" * 60)
    print("ExHentai ComicInfo.xml Extractor")
    print("=" * 60)

    # Get parent folder
    if len(sys.argv) > 1:
        parent_folder = Path(sys.argv[1])
    else:
        print("\nEnter parent folder containing gallery folders:")
        folder_input = input("Folder: ").strip()
        if not folder_input:
            print("[ERROR] No folder path provided")
            return
        parent_folder = Path(folder_input)

    if not parent_folder.exists():
        print(f"[ERROR] Folder does not exist: {parent_folder}")
        return

    # Load cookies
    if not COOKIE_FILE.exists():
        print(f"[ERROR] Cookie file not found: {COOKIE_FILE}")
        return

    fetcher = ExHentaiFetcher(COOKIE_FILE)

    # Get all gallery folders without ComicInfo.xml
    gallery_folders = []
    for folder in sorted(parent_folder.iterdir()):
        if folder.is_dir() and not folder.name.startswith('.'):
            comic_info_path = folder / "ComicInfo.xml"
            if not comic_info_path.exists():
                gallery_folders.append(folder)

    if not gallery_folders:
        print("\n[INFO] All galleries already have ComicInfo.xml!")
        return

    print(f"\n[INFO] Found {len(gallery_folders)} galleries without ComicInfo.xml")
    print("=" * 60)

    # Process each gallery
    completed = 0
    skipped = 0

    for i, gallery_folder in enumerate(gallery_folders, 1):
        print(f"\n[{i}/{len(gallery_folders)}] {gallery_folder.name}")
        print("-" * 60)

        # Ask for URL
        print("Enter gallery URL (or 's' to skip, 'q' to quit):")
        user_input = input("URL: ").strip()

        if user_input.lower() == 'q':
            print("\n[INFO] Quitting...")
            break
        elif user_input.lower() == 's':
            print("[SKIP] Skipped")
            skipped += 1
            continue

        if not validate_url(user_input):
            print("[ERROR] Invalid URL format, skipping...")
            skipped += 1
            continue

        # Fetch gallery info
        gallery_info = fetcher.fetch_gallery_info(user_input)

        if not gallery_info:
            print("[ERROR] Failed to fetch gallery info, skipping...")
            skipped += 1
            continue

        # Display fetched info
        print(f"  Title: {gallery_info.get('title_english', 'N/A')}")
        print(f"  Artist: {gallery_info.get('artist', 'N/A')}")

        # Create ComicInfo.xml
        output_path = gallery_folder / "ComicInfo.xml"
        ComicInfoGenerator.create(gallery_info, output_path)
        print(f"[SUCCESS] Created: {output_path}")
        completed += 1

    # Summary
    print("\n" + "=" * 60)
    print(f"[SUMMARY] Completed: {completed}, Skipped: {skipped}, Remaining: {len(gallery_folders) - completed - skipped}")
    print("=" * 60)


if __name__ == "__main__":
    main()
