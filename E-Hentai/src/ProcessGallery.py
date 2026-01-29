"""
Gallery Processor - Unified script for processing manga/doujinshi galleries
1. Rename images to %08d format
2. If info.txt exists, parse it to generate ComicInfo.xml
3. If no info.txt, search ExHentai/NHentai to get metadata
"""

import os
import re
import sys
import json
import time
import webbrowser
from pathlib import Path
from urllib.parse import quote
from xml.etree.ElementTree import Element, ElementTree
import requests
from bs4 import BeautifulSoup

try:
    import cloudscraper
    HAS_CLOUDSCRAPER = True
except ImportError:
    HAS_CLOUDSCRAPER = False

# Paths
SCRIPT_DIR = Path(__file__).parent.parent
CONFIG_FILE = SCRIPT_DIR / "config.json"
COOKIE_DIR = SCRIPT_DIR / "cookie"
ERROR_LOG_FILE = SCRIPT_DIR / "error_log.txt"

# Gallery link pattern
GALLERY_LINK_PATTERN = r'https://exhentai\.org/g/(\d+)/([a-f0-9]+)/?'


def clean_gallery_name(name):
    """Remove [] and () bracketed content for searching"""
    cleaned = re.sub(r'\[[^\]]*\]', '', name)
    cleaned = re.sub(r'\([^)]*\)', '', cleaned)
    cleaned = cleaned.replace('\ufffd', '')
    cleaned = re.sub(r'\s+', ' ', cleaned)
    return cleaned.strip()


def count_images_in_folder(folder_path):
    """Count image files in a folder"""
    image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.avif'}
    count = 0
    for f in folder_path.iterdir():
        if f.is_file() and f.suffix.lower() in image_extensions:
            count += 1
    return count


def rename_images_in_folder(folder_path):
    """Rename all images in folder to %08d format"""
    renamed_count = 0

    files = [f for f in folder_path.iterdir() if f.is_file()
             and f.name not in ['info.txt', 'ComicInfo.xml']]
    files.sort(key=lambda x: x.name)

    if not files:
        return 0

    for index, file_path in enumerate(files, start=1):
        extension = file_path.suffix
        new_name = f"{index:08d}{extension}"
        new_path = folder_path / new_name

        if file_path.name != new_name:
            file_path.rename(new_path)
            renamed_count += 1

    return renamed_count


class InfoTxtParser:
    """Parse info.txt from E-Hentai Downloader"""

    @staticmethod
    def parse(info_txt_path):
        """Parse info.txt and return gallery info dict"""
        with open(info_txt_path, 'r', encoding='utf-8') as f:
            content = f.read()

        lines = content.split('\n')

        info = {
            'url': '',
            'source': 'info.txt',
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

        # Line 1: English title, Line 2: Japanese title, Line 3: URL
        if len(lines) >= 1:
            info['title_english'] = lines[0].strip()
        if len(lines) >= 2:
            info['title_japanese'] = lines[1].strip()
        if len(lines) >= 3:
            url_match = re.search(GALLERY_LINK_PATTERN, lines[2])
            if url_match:
                info['url'] = url_match.group(0)

        # Parse metadata fields
        for line in lines:
            line = line.strip()

            if line.startswith('Language:'):
                info['language'] = line.replace('Language:', '').strip()
            elif line.startswith('Length:'):
                match = re.search(r'(\d+)\s*pages?', line)
                if match:
                    info['page_count'] = match.group(1)
            elif line.startswith('Rating:'):
                match = re.search(r'[\d.]+', line)
                if match:
                    info['rating'] = match.group(0)

        # Parse tags section
        in_tags = False
        artists = []
        groups = []
        characters = []
        parodies = []
        other_tags = []

        for line in lines:
            line = line.strip()

            if line == 'Tags:':
                in_tags = True
                continue

            if in_tags:
                if line.startswith('>'):
                    tag_line = line[1:].strip()
                    if ':' in tag_line:
                        tag_type, tag_values = tag_line.split(':', 1)
                        tag_type = tag_type.strip().lower()
                        tags = [t.strip() for t in tag_values.split(',')]

                        if tag_type == 'artist':
                            artists.extend(tags)
                        elif tag_type == 'group':
                            groups.extend(tags)
                        elif tag_type == 'character':
                            characters.extend(tags)
                        elif tag_type == 'parody':
                            parodies.extend(tags)
                        elif tag_type in ('female', 'male', 'mixed', 'other'):
                            other_tags.extend(tags)
                elif line and not line.startswith('>'):
                    # End of tags section
                    in_tags = False

        info['artist'] = ', '.join(artists)
        info['group'] = ', '.join(groups)
        info['characters'] = ', '.join(characters)
        info['parody'] = ', '.join(parodies)
        info['tags'] = ', '.join(other_tags)

        return info


class ExHentaiSearcher:
    """Handle ExHentai search and data extraction"""

    BASE_SEARCH_URL = "https://exhentai.org/?f_search="

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
            print(f"[EXHENTAI] Loaded {len(cookies)} cookies")
        except Exception as e:
            print(f"[EXHENTAI] Failed to load cookies: {e}")
        return cookies

    def search_gallery(self, gallery_name):
        """Search for gallery and return results with page counts"""
        url = self.BASE_SEARCH_URL + quote(gallery_name, safe='')

        try:
            print(f"[EXHENTAI] Searching: {gallery_name}")
            print(f"[EXHENTAI] URL: {url}")
            response = self.session.get(url, timeout=10)
            response.raise_for_status()

            soup = BeautifulSoup(response.content, 'html.parser')

            gallery_results = []  # List of (url, page_count)
            seen_urls = set()

            # Parse thumbnail view (gl1t divs)
            for gallery_div in soup.find_all('div', class_='gl1t'):
                link = gallery_div.find('a', href=re.compile(GALLERY_LINK_PATTERN))
                if not link:
                    continue
                href = link.get('href')
                if href in seen_urls:
                    continue
                seen_urls.add(href)

                # Extract page count from gl5t div
                page_count = 0
                gl5t = gallery_div.find('div', class_='gl5t')
                if gl5t:
                    # Find the specific div containing "X pages" text
                    for div in gl5t.find_all('div'):
                        text = div.get_text().strip()
                        match = re.match(r'^(\d+)\s*pages?$', text, re.IGNORECASE)
                        if match:
                            page_count = int(match.group(1))
                            break

                gallery_results.append((href, page_count))

            # Fallback: if no gl1t found, try other views (extended/compact)
            if not gallery_results:
                for link in soup.find_all('a', href=re.compile(GALLERY_LINK_PATTERN)):
                    href = link.get('href')
                    if href not in seen_urls:
                        seen_urls.add(href)
                        gallery_results.append((href, 0))  # No page count available

            print(f"[EXHENTAI] Found {len(gallery_results)} results")
            return gallery_results, url

        except Exception as e:
            print(f"[EXHENTAI] Search failed: {e}")
            return [], url

    def fetch_gallery_info(self, gallery_url):
        """Fetch and extract gallery information"""
        try:
            response = self.session.get(gallery_url, timeout=10)
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
            print(f"[EXHENTAI] Failed to fetch gallery: {e}")
            return None


class NHentaiSearcher:
    """Handle NHentai search and data extraction"""

    BASE_SEARCH_URL = "https://nhentai.net/search/?q="

    def __init__(self, cookie_file_path=None):
        if HAS_CLOUDSCRAPER:
            self.session = cloudscraper.create_scraper()
        else:
            self.session = requests.Session()

        if cookie_file_path and Path(cookie_file_path).exists():
            cookies = self._load_cookies(cookie_file_path)
            self.session.cookies.update(cookies)

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
        except:
            pass
        return cookies

    def search_gallery(self, gallery_name):
        """Search for gallery and return results"""
        url = self.BASE_SEARCH_URL + quote(gallery_name, safe='')

        try:
            print(f"[NHENTAI] Searching: {gallery_name}")
            print(f"[NHENTAI] URL: {url}")
            response = self.session.get(url, timeout=10)
            print(f"[NHENTAI] Status: {response.status_code}, Length: {len(response.content)} bytes")
            response.raise_for_status()

            soup = BeautifulSoup(response.content, 'html.parser')

            # Debug: print page title
            title = soup.find('title')
            if title:
                print(f"[NHENTAI] Page title: {title.get_text()}")

            gallery_links = []

            # Find gallery links - they are <a class="cover"> inside <div class="gallery">
            for gallery_div in soup.find_all('div', class_='gallery'):
                link = gallery_div.find('a', class_='cover')
                if link:
                    href = link.get('href')
                    if href and '/g/' in href:
                        if not href.startswith('http'):
                            href = 'https://nhentai.net' + href
                        href = href.rstrip('/')
                        if href not in gallery_links:
                            gallery_links.append(href)

            print(f"[NHENTAI] Found {len(gallery_links)} results")
            return gallery_links, url

        except Exception as e:
            print(f"[NHENTAI] Search failed: {e}")
            return [], url

    def fetch_gallery_info(self, gallery_url):
        """Fetch and extract gallery information"""
        try:
            time.sleep(1)
            response = self.session.get(gallery_url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            info = {
                'url': gallery_url,
                'source': 'nhentai',
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

            title_elem = soup.find('h1', class_='title')
            if title_elem:
                span = title_elem.find('span', class_='pretty')
                info['title_english'] = span.get_text().strip() if span else title_elem.get_text().strip()

            jp_title = soup.find('h2', class_='title')
            if jp_title:
                span = jp_title.find('span', class_='pretty')
                info['title_japanese'] = span.get_text().strip() if span else jp_title.get_text().strip()

            for container in soup.find_all('div', class_='tag-container'):
                text = container.get_text()
                label = text.split(':')[0].strip() if ':' in text else ''

                tag_links = container.find_all('a', class_='tag')
                tag_names = [t.find('span', class_='name').get_text().strip()
                            for t in tag_links if t.find('span', class_='name')]

                if label == 'Parodies':
                    info['parody'] = ', '.join(tag_names)
                elif label == 'Characters':
                    info['characters'] = ', '.join(tag_names)
                elif label == 'Tags':
                    info['tags'] = ', '.join(tag_names)
                elif label == 'Artists':
                    info['artist'] = ', '.join(tag_names)
                elif label == 'Groups':
                    info['group'] = ', '.join(tag_names)
                elif label == 'Languages':
                    info['language'] = ', '.join(tag_names)
                elif label == 'Pages':
                    if tag_names:
                        info['page_count'] = tag_names[0]

            return info

        except Exception as e:
            print(f"[NHENTAI] Failed to fetch gallery: {e}")
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


class GalleryProcessor:
    """Main processor"""

    def __init__(self, gallery_parent_dir):
        self.gallery_dir = Path(gallery_parent_dir)
        self.errors = []

        exhentai_cookie = COOKIE_DIR / "cookie_exhentai.txt"
        nhentai_cookie = COOKIE_DIR / "cookie_nhentai.txt"

        self.exhentai = None
        self.nhentai = None

        if exhentai_cookie.exists():
            self.exhentai = ExHentaiSearcher(exhentai_cookie)
        else:
            print("[WARNING] ExHentai cookie not found")

        self.nhentai = NHentaiSearcher(nhentai_cookie if nhentai_cookie.exists() else None)

    def user_select_gallery(self, gallery_results, gallery_name, search_url, local_page_count=None):
        """Let user choose from multiple results

        Args:
            gallery_results: List of (url, page_count) tuples or list of urls
            gallery_name: Name of the gallery being searched
            search_url: URL to open in browser
            local_page_count: Number of images in local folder (for display)
        """
        # Normalize to list of tuples
        if gallery_results and not isinstance(gallery_results[0], tuple):
            gallery_results = [(url, 0) for url in gallery_results]

        print(f"\n[MULTIPLE] Found {len(gallery_results)} results for: {gallery_name}")
        if local_page_count:
            print(f"[INFO] Local folder has {local_page_count} images")
        print("=" * 70)

        try:
            webbrowser.open(search_url)
        except:
            pass

        for i, (link, page_count) in enumerate(gallery_results, 1):
            if page_count > 0:
                match_indicator = " <-- MATCH" if local_page_count and page_count == local_page_count else ""
                print(f"{i}. [{page_count} pages]{match_indicator} {link}")
            else:
                print(f"{i}. {link}")

        print(f"\n0 to skip, 1-{len(gallery_results)} to select")

        while True:
            try:
                choice = int(input("Choice: ").strip())
                if choice == 0:
                    return None
                if 1 <= choice <= len(gallery_results):
                    return gallery_results[choice - 1][0]
            except ValueError:
                pass
            print("Invalid choice")

    def search_online(self, gallery_name, local_page_count=0):
        """Search ExHentai first, fall back to NHentai

        Args:
            gallery_name: Name of the gallery to search
            local_page_count: Number of images in local folder for auto-selection
        """
        cleaned_name = clean_gallery_name(gallery_name)
        if cleaned_name != gallery_name:
            print(f"[INFO] Cleaned name: {cleaned_name}")

        # Try ExHentai
        if self.exhentai:
            results, search_url = self.exhentai.search_gallery(cleaned_name)
            if results:
                selected = None

                if len(results) == 1:
                    selected = results[0][0]  # results is list of (url, page_count)
                elif local_page_count > 0 and len(results) <= 20:
                    # Try auto-selection based on page count
                    matching = [r for r in results if r[1] == local_page_count]
                    if len(matching) == 1:
                        print(f"[AUTO] Found unique match with {local_page_count} pages: {matching[0][0]}")
                        selected = matching[0][0]
                    elif len(matching) == 0:
                        print(f"[INFO] No galleries match local page count ({local_page_count})")
                        selected = self.user_select_gallery(results, cleaned_name, search_url, local_page_count)
                    else:
                        print(f"[INFO] Multiple galleries ({len(matching)}) match local page count ({local_page_count})")
                        selected = self.user_select_gallery(results, cleaned_name, search_url, local_page_count)
                else:
                    if len(results) > 20:
                        print(f"[INFO] Too many results ({len(results)}) for auto-selection, manual input required")
                    selected = self.user_select_gallery(results, cleaned_name, search_url, local_page_count)

                if selected:
                    info = self.exhentai.fetch_gallery_info(selected)
                    if info:
                        return info

        # Fall back to NHentai
        print("[INFO] Trying NHentai...")
        results, search_url = self.nhentai.search_gallery(cleaned_name)
        if results:
            if len(results) == 1:
                selected = results[0]
            else:
                selected = self.user_select_gallery(results, cleaned_name, search_url, local_page_count)

            if selected:
                return self.nhentai.fetch_gallery_info(selected)

        return None

    def process_folder(self, folder_path):
        """Process a single gallery folder"""
        gallery_name = folder_path.name

        print(f"\n{'=' * 70}")
        print(f"Processing: {gallery_name}")
        print('=' * 70)

        # Skip if ComicInfo.xml already exists
        comic_info_path = folder_path / "ComicInfo.xml"
        if comic_info_path.exists():
            print("[SKIP] ComicInfo.xml already exists")
            return True

        # Rename images
        renamed = rename_images_in_folder(folder_path)
        if renamed > 0:
            print(f"[INFO] Renamed {renamed} images")

        # Count images for auto-selection
        local_page_count = count_images_in_folder(folder_path)
        print(f"[INFO] Local folder has {local_page_count} images")

        # Check for info.txt
        info_txt_path = folder_path / "info.txt"
        gallery_info = None

        if info_txt_path.exists():
            print("[INFO] Found info.txt, parsing...")
            try:
                gallery_info = InfoTxtParser.parse(info_txt_path)
                if not gallery_info.get('url'):
                    print("[WARNING] No gallery URL in info.txt, searching online...")
                    gallery_info = None
            except Exception as e:
                print(f"[ERROR] Failed to parse info.txt: {e}")

        # If no info.txt or parsing failed, search online
        if not gallery_info:
            print("[INFO] Searching online...")
            gallery_info = self.search_online(gallery_name, local_page_count)

        if not gallery_info:
            error = f"[{gallery_name}] No results found"
            print(f"[ERROR] {error}")
            self.errors.append(error)
            return False

        # Create ComicInfo.xml
        ComicInfoGenerator.create(gallery_info, comic_info_path)
        print(f"[SUCCESS] Created ComicInfo.xml (source: {gallery_info.get('source', 'unknown')})")
        print(f"  Title: {gallery_info.get('title_english', 'N/A')}")
        print(f"  Artist: {gallery_info.get('artist', 'N/A')}")

        return True

    def process_all(self):
        """Process all gallery folders"""
        if not self.gallery_dir.exists():
            print(f"[ERROR] Directory not found: {self.gallery_dir}")
            return

        folders = [f for f in self.gallery_dir.iterdir()
                   if f.is_dir() and not f.name.startswith('.')]

        print(f"[INFO] Found {len(folders)} gallery folders")

        success = 0
        for folder in sorted(folders):
            if self.process_folder(folder):
                success += 1

        print(f"\n{'=' * 70}")
        print(f"[SUMMARY] Processed: {success}/{len(folders)}")
        print(f"[SUMMARY] Errors: {len(self.errors)}")

        if self.errors:
            with open(ERROR_LOG_FILE, 'a', encoding='utf-8') as f:
                for error in self.errors:
                    f.write(f"{error}\n")
            print(f"[INFO] Errors saved to {ERROR_LOG_FILE}")


def main():
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        config = json.load(f)

    gallery_dir = Path(config["gallery_parent_dir"])

    if len(sys.argv) > 1:
        gallery_dir = Path(sys.argv[1])

    print("Gallery Processor")
    print("=" * 70)
    print(f"Directory: {gallery_dir}")
    print("=" * 70)

    processor = GalleryProcessor(gallery_dir)
    processor.process_all()


if __name__ == "__main__":
    main()
