"""
Search ExHentai for gallery information and generate ComicInfo.xml
Scans gallery folders and creates search URLs for their names
"""

import os
import re
import sys
import json
import webbrowser
from pathlib import Path
from urllib.parse import quote
from xml.etree.ElementTree import Element, ElementTree
import requests
from bs4 import BeautifulSoup
from datetime import datetime


class ExHentaiSearcher:
    """Handle ExHentai search and data extraction"""
    
    BASE_SEARCH_URL = "https://exhentai.org/?f_search="
    GALLERY_URL_PATTERN = r'https://exhentai\.org/g/(\d+)/([a-f0-9]+)/?'
    
    def __init__(self, cookie_file_path):
        """Initialize with cookie file for authentication"""
        self.cookie_file = cookie_file_path
        self.cookies = self._load_cookies()
        self.session = requests.Session()
        self.session.cookies.update(self.cookies)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def _load_cookies(self):
        """Load cookies from Netscape format cookie file"""
        cookies = {}
        try:
            with open(self.cookie_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split('\t')
                    if len(parts) >= 7:
                        domain, flag, path, secure, expiration, name, value = parts[:7]
                        cookies[name] = value
            
            print(f"[INFO] Loaded {len(cookies)} cookies from {self.cookie_file}")
            return cookies
        except Exception as e:
            print(f"[ERROR] Failed to load cookies: {e}")
            return {}
    
    def build_search_url(self, gallery_name):
        """Build ExHentai search URL with proper encoding"""
        encoded_name = quote(gallery_name, safe='')
        return self.BASE_SEARCH_URL + encoded_name
    
    def search_gallery(self, gallery_name):
        """Search for gallery and return results"""
        url = self.build_search_url(gallery_name)
        
        try:
            print(f"[SEARCH] Searching: {gallery_name}")
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            # Parse search results
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract gallery links from search results
            gallery_links = []
            for link in soup.find_all('a', href=re.compile(self.GALLERY_URL_PATTERN)):
                href = link.get('href')
                # Avoid duplicate links
                if href not in gallery_links:
                    gallery_links.append(href)
            
            return gallery_links, url
            
        except Exception as e:
            print(f"[ERROR] Search failed for '{gallery_name}': {e}")
            return [], url
    
    def fetch_gallery_page(self, gallery_url):
        """Fetch and parse a specific gallery page"""
        try:
            response = self.session.get(gallery_url, timeout=10)
            response.raise_for_status()
            return response.content
        except Exception as e:
            print(f"[ERROR] Failed to fetch gallery page: {e}")
            return None
    
    def extract_gallery_info(self, html_content, gallery_url):
        """Extract gallery information from gallery page"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            info = {
                'url': gallery_url,
                'title_english': '',
                'title_japanese': '',
                'artist': '',
                'group': '',
                'characters': '',
                'tags': '',
                'page_count': '',
                'rating': '',
                'language': ''
            }
            
            # Extract English title
            gn_tag = soup.find(id='gn')
            if gn_tag:
                info['title_english'] = gn_tag.get_text().strip()
            
            # Extract Japanese title
            gj_tag = soup.find(id='gj')
            if gj_tag:
                info['title_japanese'] = gj_tag.get_text().strip()
            
            # Extract page count
            for td in soup.find_all('td', class_='gdt1'):
                if td.get_text().strip() == 'Length:':
                    length_td = td.find_next('td', class_='gdt2')
                    if length_td:
                        pages = length_td.get_text().strip()
                        # Extract number from "16 pages"
                        match = re.search(r'(\d+)\s*pages?', pages)
                        if match:
                            info['page_count'] = match.group(1)
            
            # Extract language
            for td in soup.find_all('td', class_='gdt1'):
                if td.get_text().strip() == 'Language:':
                    lang_td = td.find_next('td', class_='gdt2')
                    if lang_td:
                        info['language'] = lang_td.get_text().strip()
            
            # Extract rating
            rating_label = soup.find(id='rating_label')
            if rating_label:
                rating_text = rating_label.get_text().strip()
                match = re.search(r'[\d.]+', rating_text)
                if match:
                    info['rating'] = match.group(0)
            
            # Extract tags (group, artist, etc)
            tag_rows = soup.find_all('tr')
            for row in tag_rows:
                td_list = row.find_all('td')
                if len(td_list) >= 2:
                    tag_type = td_list[0].get_text().strip().lower()
                    tag_content_td = td_list[1]
                    
                    if tag_type == 'group:':
                        tags = [a.get_text() for a in tag_content_td.find_all('a')]
                        info['group'] = ', '.join(tags)
                    elif tag_type == 'artist:':
                        tags = [a.get_text() for a in tag_content_td.find_all('a')]
                        info['artist'] = ', '.join(tags)
                    elif tag_type == 'characters:':
                        tags = [a.get_text() for a in tag_content_td.find_all('a')]
                        info['characters'] = ', '.join(tags)
                    elif tag_type == 'female:' or tag_type == 'male:' or tag_type == 'mixed:' or tag_type == 'other:':
                        tags = [a.get_text() for a in tag_content_td.find_all('a')]
                        if info['tags']:
                            info['tags'] += ', ' + ', '.join(tags)
                        else:
                            info['tags'] = ', '.join(tags)
            
            return info
            
        except Exception as e:
            print(f"[ERROR] Failed to extract gallery info: {e}")
            return None


class ComicInfoGenerator:
    """Generate ComicInfo.xml files"""
    
    @staticmethod
    def create_comic_info_xml(gallery_info, output_path):
        """Create ComicInfo.xml file from gallery information"""
        try:
            # Create root element
            root = Element('ComicInfo')
            root.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
            root.set('xsi:noNamespaceSchemaLocation',
                    'https://raw.githubusercontent.com/anansi-project/comicinfo/main/schema/v2.0/ComicInfo.xsd')
            
            # Add basic info
            if gallery_info['title_english']:
                series_elem = Element('Series')
                series_elem.text = gallery_info['title_english']
                root.append(series_elem)
            
            if gallery_info['title_japanese']:
                alt_series = Element('AlternateSeries')
                alt_series.text = gallery_info['title_japanese']
                root.append(alt_series)
            
            if gallery_info['artist']:
                artist_elem = Element('Penciller')
                artist_elem.text = gallery_info['artist']
                root.append(artist_elem)
            
            if gallery_info['group']:
                writer_elem = Element('Writer')
                writer_elem.text = gallery_info['group']
                root.append(writer_elem)
            
            if gallery_info['characters']:
                characters_elem = Element('Characters')
                characters_elem.text = gallery_info['characters']
                root.append(characters_elem)
            
            if gallery_info['tags']:
                genre_elem = Element('Genre')
                genre_elem.text = gallery_info['tags']
                root.append(genre_elem)
            
            if gallery_info['page_count']:
                pages_elem = Element('PageCount')
                pages_elem.text = gallery_info['page_count']
                root.append(pages_elem)
            
            if gallery_info['rating']:
                rating_elem = Element('CommunityRating')
                rating_elem.text = gallery_info['rating']
                root.append(rating_elem)
            
            # Add URL
            web_elem = Element('Web')
            web_elem.text = gallery_info['url']
            root.append(web_elem)
            
            # Write to file
            tree = ElementTree(root)
            tree.write(output_path, encoding='utf-8', xml_declaration=True)
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to create ComicInfo.xml: {e}")
            return False


class GalleryProcessor:
    """Main processor for scanning and adding info to galleries"""
    
    def __init__(self, gallery_parent_dir, cookie_file_path, error_log_path):
        """Initialize the processor"""
        self.gallery_parent_dir = Path(gallery_parent_dir)
        self.cookie_file = Path(cookie_file_path)
        self.error_log = Path(error_log_path)
        self.searcher = ExHentaiSearcher(self.cookie_file)
        self.errors = []
    
    def user_select_gallery(self, gallery_links, gallery_name):
        """Display gallery options and let user choose, open browser"""
        print(f"\n[MULTIPLE] Found {len(gallery_links)} results for: {gallery_name}")
        print("="*70)
        
        # Open search page in Chrome browser
        search_url = self.searcher.build_search_url(gallery_name)
        try:
            import subprocess
            subprocess.Popen(['chrome.exe', search_url])
            print(f"[INFO] Opening Chrome: {search_url}")
            print(f"[INFO] View the results in Chrome and select from the options below...\n")
        except Exception as e:
            print(f"[INFO] Could not open Chrome: {e}")
            print(f"[INFO] Open manually: {search_url}\n")
        
        for i, link in enumerate(gallery_links, 1):
            print(f"{i}. {link}")
        
        print("\nOptions: Type 1-" + str(len(gallery_links)) + " to select, 0 to skip")
        print("="*70)
        
        while True:
            try:
                choice = input("Your choice: ").strip()
                choice_num = int(choice)
                
                if choice_num == 0:
                    return None
                elif 1 <= choice_num <= len(gallery_links):
                    return gallery_links[choice_num - 1]
                else:
                    print(f"Please enter a number between 0 and {len(gallery_links)}")
            except ValueError:
                print("Please enter a valid number")
    
    def process_gallery_folder(self, folder_path):
        """Process a single gallery folder"""
        gallery_name = folder_path.name
        
        # Search for gallery
        results, search_url = self.searcher.search_gallery(gallery_name)
        
        if not results:
            error_msg = f"[{gallery_name}] No search results found"
            print(f"[ERROR] {error_msg}")
            self.errors.append(error_msg)
            return False
        
        # Determine which gallery to use
        if len(results) == 1:
            selected_url = results[0]
            print(f"[SUCCESS] Found 1 result: {selected_url}")
        else:
            selected_url = self.user_select_gallery(results, gallery_name)
            if selected_url is None:
                error_msg = f"[{gallery_name}] Skipped by user"
                print(f"[SKIP] {error_msg}")
                self.errors.append(error_msg)
                return False
        
        # Fetch gallery page
        html_content = self.searcher.fetch_gallery_page(selected_url)
        if not html_content:
            error_msg = f"[{gallery_name}] Failed to fetch gallery page"
            print(f"[ERROR] {error_msg}")
            self.errors.append(error_msg)
            return False
        
        # Extract gallery info
        gallery_info = self.searcher.extract_gallery_info(html_content, selected_url)
        if not gallery_info:
            error_msg = f"[{gallery_name}] Failed to extract gallery info"
            print(f"[ERROR] {error_msg}")
            self.errors.append(error_msg)
            return False
        
        # Create ComicInfo.xml
        comic_info_path = folder_path / "ComicInfo.xml"
        if ComicInfoGenerator.create_comic_info_xml(gallery_info, comic_info_path):
            print(f"[SUCCESS] Created ComicInfo.xml: {comic_info_path}")
            print(f"  Title: {gallery_info['title_english']}")
            print(f"  Pages: {gallery_info['page_count']}")
            print(f"  Rating: {gallery_info['rating']}")
            return True
        else:
            error_msg = f"[{gallery_name}] Failed to create ComicInfo.xml"
            print(f"[ERROR] {error_msg}")
            self.errors.append(error_msg)
            return False
    
    def process_all_galleries(self):
        """Process all gallery folders in parent directory"""
        if not self.gallery_parent_dir.exists():
            print(f"[ERROR] Directory not found: {self.gallery_parent_dir}")
            return False
        
        # Find all gallery folders
        gallery_folders = [
            f for f in self.gallery_parent_dir.iterdir()
            if f.is_dir() and not f.name.startswith('.')
        ]
        
        if not gallery_folders:
            print(f"[WARNING] No gallery folders found in {self.gallery_parent_dir}")
            return False
        
        print(f"[INFO] Found {len(gallery_folders)} gallery folders")
        print("="*70)
        
        processed_count = 0
        for folder in sorted(gallery_folders):
            # Skip if ComicInfo.xml already exists
            if (folder / "ComicInfo.xml").exists():
                print(f"[SKIP] ComicInfo.xml already exists: {folder.name}")
                continue
            
            success = self.process_gallery_folder(folder)
            if success:
                processed_count += 1
            
            print()
        
        # Save error log
        self._save_error_log()
        
        print("="*70)
        print(f"[SUMMARY] Processed: {processed_count}/{len(gallery_folders)} galleries")
        print(f"[SUMMARY] Errors: {len(self.errors)}")
        
        return True
    
    def _save_error_log(self):
        """Save errors to log file"""
        if not self.errors:
            return
        
        try:
            with open(self.error_log, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*70}\n")
                f.write(f"Error Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"{'='*70}\n\n")
                
                for error in self.errors:
                    f.write(f"{error}\n")
            
            print(f"[INFO] Errors saved to {self.error_log}")
            
        except Exception as e:
            print(f"[ERROR] Failed to save error log: {e}")


def main():
    """Main entry point"""
    # Load configuration from config.json
    script_dir = Path(__file__).parent.parent
    config_file = script_dir / "config.json"
    
    with open(config_file, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    default_gallery_dir = Path(config["addinfo_default_gallery_dir"])
    cookie_file = script_dir / config["cookie_file"]
    error_log = script_dir / config["error_log_file"]
    
    # Allow custom gallery directory as argument
    if len(sys.argv) > 1:
        gallery_dir = Path(sys.argv[1])
    else:
        gallery_dir = default_gallery_dir
    
    print("ExHentai Gallery Info Searcher")
    print("="*70)
    print(f"Gallery Directory: {gallery_dir}")
    print(f"Cookie File: {cookie_file}")
    print(f"Error Log: {error_log}")
    print("="*70 + "\n")
    
    # Check if cookie file exists
    if not cookie_file.exists():
        print(f"[ERROR] Cookie file not found: {cookie_file}")
        print("[ERROR] Please ensure the cookie file exists in E-Hentai/cookie/")
        return
    
    # Process galleries
    processor = GalleryProcessor(gallery_dir, cookie_file, error_log)
    processor.process_all_galleries()


if __name__ == "__main__":
    main()
