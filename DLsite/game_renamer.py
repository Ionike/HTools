#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Game Folder Renamer with Local LLM Integration
Automatically identifies and renames Japanese game folders using LMStudio and web search
Format: [YYMMDD][RJ########][Author]Game Name
Example: [250125][RJ01023407][Topyu_u]紫森リチュアル
"""

import os
import json
import re
import sys
import time
from pathlib import Path
from datetime import datetime
import subprocess
from typing import Optional, Dict, List, Tuple
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('game_renamer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

try:
    import requests
    from urllib.parse import quote
except ImportError:
    logger.error("Required packages not installed. Install with: pip install requests")
    sys.exit(1)


class LMStudioClient:
    """Client for communicating with LMStudio local LLM"""
    
    def __init__(self, host: str = "localhost", port: int = 1234):
        self.base_url = f"http://{host}:{port}"
        self.api_url = f"{self.base_url}/v1/chat/completions"
        
    def check_connection(self) -> bool:
        """Check if LMStudio is running"""
        try:
            response = requests.get(f"{self.base_url}/api/status", timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Cannot connect to LMStudio: {e}")
            return False
    
    def query(self, prompt: str, temperature: float = 0.7) -> Optional[str]:
        """Query the LLM with a prompt"""
        try:
            payload = {
                "model": "local-model",
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "temperature": temperature,
                "max_tokens": 1000
            }
            
            response = requests.post(self.api_url, json=payload, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            if 'choices' in result and len(result['choices']) > 0:
                return result['choices'][0]['message']['content'].strip()
            return None
        except Exception as e:
            logger.error(f"LLM query failed: {e}")
            return None


class GameFolderAnalyzer:
    """Analyzes game folders to extract identifying information"""
    
    def __init__(self, llm_client: LMStudioClient):
        self.llm = llm_client
        self.important_extensions = {
            '.exe', '.bat', '.com', '.cmd',  # Executables
            '.txt', '.md', '.readme',  # Documentation
        }
        
    def get_files_in_folder(self, folder_path: str) -> Dict[str, List[str]]:
        """Extract file names and important files from a folder"""
        files_info = {
            'all_files': [],
            'executables': [],
            'readmes': [],
            'dlsite_links': []
        }
        
        try:
            for root, dirs, files in os.walk(folder_path):
                # Limit depth to avoid going too deep
                depth = root.replace(folder_path, '').count(os.sep)
                if depth > 3:
                    continue
                    
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, folder_path)
                    
                    files_info['all_files'].append(rel_path)
                    
                    # Check for executables
                    if os.path.splitext(file)[1].lower() in {'.exe', '.bat', '.com', '.cmd'}:
                        files_info['executables'].append(file)
                    
                    # Check for readme files
                    if self._is_readme(file):
                        files_info['readmes'].append(file)
                        
                        # Try to read readme content
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read(500)  # First 500 chars
                                if content:
                                    files_info['readmes'].append(f"CONTENT:{file}: {content}")
                        except:
                            pass
                    
                    # Check for dlsite links in file names
                    if 'dlsite' in file.lower() or 'rj' in file.lower():
                        files_info['dlsite_links'].append(file)
        except Exception as e:
            logger.error(f"Error analyzing folder {folder_path}: {e}")
        
        return files_info
    
    def _is_readme(self, filename: str) -> bool:
        """Check if file is a readme or documentation file"""
        readme_patterns = [
            'readme', 'readme.txt', 'readme.md',
            'お読みください', '説明書', 'manual', 'guide',
            'instruction', '注意', 'info', 'credits', 'credit'
        ]
        name_lower = filename.lower()
        return any(pattern in name_lower for pattern in readme_patterns)
    
    def identify_game(self, folder_name: str, files_info: Dict) -> Optional[str]:
        """Use LLM to identify the game from folder structure"""
        
        # Prepare prompt for LLM
        prompt = f"""Analyze the following game folder information to identify the game name.
        
Folder Name: {folder_name}
Files in folder: {', '.join(files_info['all_files'][:10])}
Executables: {', '.join(files_info['executables'])}
Readme/Documentation files: {', '.join(files_info['readmes'][:5])}
DLsite-related files: {', '.join(files_info['dlsite_links'])}

Please identify:
1. Is this a game or software?
2. What is the likely name of the game/work?
3. What platform might it be from (DLsite, other)?
4. Extract any RJ numbers if visible (format: RJ########)

Respond in JSON format:
{{"is_game": true/false, "game_name": "name", "platform": "dlsite/other", "rj_number": "RJ01023407 or null"}}

Only respond with JSON, no extra text."""

        response = self.llm.query(prompt)
        if response:
            logger.info(f"LLM Response: {response}")
            try:
                result = json.loads(response)
                return result
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse LLM response: {response}")
        
        return None


class DLsiteSearcher:
    """Searches Google for DLsite games with proxy support"""
    
    def __init__(self, llm_client: LMStudioClient, use_proxy: bool = True):
        self.llm = llm_client
        self.use_proxy = use_proxy
        self.session = requests.Session()
        self._setup_proxy()
        
    def _setup_proxy(self):
        """Set up system proxy for requests"""
        if self.use_proxy:
            # Windows system proxy detection
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
                    logger.info(f"Using system proxy: {proxy_server}")
            except Exception as e:
                logger.warning(f"Could not configure system proxy: {e}")
    
    def search_dlsite(self, game_name: str, use_google: bool = True) -> List[Dict]:
        """Search for game on DLsite using Google with system proxy"""
        
        search_query = f"{game_name} dlsite"
        logger.info(f"Searching for: {search_query}")
        
        results = []
        
        if use_google:
            # Use Google search with proxy
            try:
                # Note: Direct Google search is blocked, use alternative approach
                results = self._search_google(search_query)
            except Exception as e:
                logger.warning(f"Google search failed: {e}")
                results = []
        
        # Fall back to direct DLsite search
        if not results:
            results = self._search_dlsite_directly(game_name)
        
        return results
    
    def _search_google(self, query: str) -> List[Dict]:
        """Search Google for results (using proxy)"""
        try:
            # Using duckduckgo as alternative since Google blocks automated requests
            search_url = f"https://duckduckgo.com/search"
            params = {'q': query, 'format': 'json'}
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = self.session.get(search_url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            
            results = []
            # Parse results (simplified)
            if 'dlsite.com' in response.text:
                results.append({
                    'title': query,
                    'link': f"https://www.dlsite.com/maniax/search?keyword={quote(query)}",
                    'source': 'dlsite_search'
                })
            
            return results
        except Exception as e:
            logger.error(f"Search error: {e}")
            return []
    
    def _search_dlsite_directly(self, game_name: str) -> List[Dict]:
        """Search DLsite directly"""
        try:
            search_url = f"https://www.dlsite.com/maniax/search?keyword={quote(game_name)}"
            logger.info(f"Searching DLsite: {search_url}")
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = self.session.get(search_url, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Return the search page link
            return [{
                'title': game_name,
                'link': search_url,
                'source': 'dlsite_direct'
            }]
        except Exception as e:
            logger.error(f"DLsite search failed: {e}")
            return []
    
    def choose_link_with_llm(self, game_name: str, search_results: List[Dict]) -> Optional[str]:
        """Use LLM to choose the best link from search results"""
        
        if not search_results:
            return None
        
        prompt = f"""Given these search results for "{game_name}", which is most likely to be the correct DLsite product page?

Search Results:
"""
        for i, result in enumerate(search_results, 1):
            prompt += f"\n{i}. {result['title']}\n   Link: {result['link']}"
        
        prompt += f"""\n\nRespond with ONLY the number (1, 2, 3, etc) of the best result, or "none" if none are relevant.
If the URL already shows it's a DLsite work page with an RJ number, choose that one.
Look for URLs like: https://www.dlsite.com/*/work/=/product_id/RJ########.html"""

        response = self.llm.query(prompt, temperature=0.3)
        
        if response and response.strip().isdigit():
            idx = int(response.strip()) - 1
            if 0 <= idx < len(search_results):
                return search_results[idx]['link']
        
        return None


class DLsiteScraper:
    """Scrapes DLsite product pages for metadata"""
    
    def __init__(self, use_proxy: bool = True):
        self.session = requests.Session()
        self.use_proxy = use_proxy
        self._setup_proxy()
        
    def _setup_proxy(self):
        """Set up system proxy"""
        if self.use_proxy:
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
    
    def extract_metadata(self, url: str) -> Optional[Dict]:
        """Extract metadata from DLsite product page"""
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            html = response.text
            
            # Extract RJ number from URL
            rj_match = re.search(r'RJ(\d+)', url)
            rj_number = f"RJ{rj_match.group(1)}" if rj_match else None
            
            # Extract game name from title or HTML
            title_match = re.search(r'<title>([^|<]+)', html)
            game_name = title_match.group(1).strip() if title_match else None
            
            # Extract author/creator name
            # Look for patterns like "creator:" or "作者" or "作品者" or text in brackets
            author = None
            
            # Try to extract from title brackets [Author]
            title_bracket_match = re.search(r'\[([^\]]+)\]', game_name) if game_name else None
            if title_bracket_match:
                potential_author = title_bracket_match.group(1)
                # Check if it looks like an author name (not a date or category)
                if not re.match(r'^\d+', potential_author) and 'OFF' not in potential_author:
                    author = potential_author
            
            # Try to extract from HTML meta tags or content
            if not author:
                creator_patterns = [
                    r'<.*?著者.*?>([^<]+)',
                    r'<.*?作者.*?>([^<]+)',
                    r'<.*?作品者.*?>([^<]+)',
                    r'creator["\']?\s*:\s*["\']?([^"\'<\n]+)',
                    r'著者["\']?\s*:\s*["\']?([^"\'<\n]+)',
                ]
                for pattern in creator_patterns:
                    creator_match = re.search(pattern, html)
                    if creator_match:
                        author = creator_match.group(1).strip()
                        break
            
            # Try to extract 販売日 (release date)
            # Common patterns for release date in DLsite
            date_patterns = [
                r'販売日\s*[：:]\s*(\d{4})[/\-](\d{1,2})[/\-](\d{1,2})',
                r'販売日\s*</.*?>\s*(\d{4})[/\-](\d{1,2})[/\-](\d{1,2})',
                r'<.*?販売日.*?>.*?(\d{4})[/\-](\d{1,2})[/\-](\d{1,2})',
            ]
            
            release_date = None
            for pattern in date_patterns:
                match = re.search(pattern, html)
                if match:
                    year, month, day = match.groups()
                    release_date = f"{year}{month.zfill(2)}{day.zfill(2)}"
                    break
            
            # If game_name contains unwanted characters, clean it
            if game_name:
                # Remove common prefixes/suffixes
                game_name = re.sub(r'\s*[\[\(].*?[\]\)]', '', game_name)
                game_name = re.sub(r'\s*\|.*$', '', game_name)
                game_name = game_name.strip()
            
            return {
                'rj_number': rj_number,
                'game_name': game_name,
                'author': author,
                'release_date': release_date,
                'url': url,
                'valid': bool(rj_number and game_name)
            }
        except Exception as e:
            logger.error(f"Failed to scrape {url}: {e}")
            return None


class GameRenamer:
    """Main class to orchestrate the game folder renaming process"""
    
    def __init__(self, root_folder: str):
        self.root_folder = root_folder
        
        # Initialize components
        self.llm = LMStudioClient()
        if not self.llm.check_connection():
            raise RuntimeError("Cannot connect to LMStudio. Make sure it's running on localhost:1234")
        
        self.analyzer = GameFolderAnalyzer(self.llm)
        self.searcher = DLsiteSearcher(self.llm)
        self.scraper = DLsiteScraper()
        
        self.results = {
            'renamed': [],
            'not_renamed': [],
            'errors': []
        }
        
    def run(self):
        """Main execution method"""
        logger.info(f"Starting game folder analysis in: {self.root_folder}")
        
        # Get all game folders
        game_folders = self._get_game_folders()
        logger.info(f"Found {len(game_folders)} potential game folders")
        
        for i, folder_path in enumerate(game_folders, 1):
            logger.info(f"\n[{i}/{len(game_folders)}] Processing: {os.path.basename(folder_path)}")
            self._process_folder(folder_path)
        
        # Save results
        self._save_results()
        self._print_summary()
    
    def _get_game_folders(self) -> List[str]:
        """Get list of game folders in root directory"""
        folders = []
        try:
            for item in os.listdir(self.root_folder):
                item_path = os.path.join(self.root_folder, item)
                if os.path.isdir(item_path) and item not in {'.', '..', '__pycache__', 'DLsite'}:
                    folders.append(item_path)
        except Exception as e:
            logger.error(f"Error reading folders: {e}")
        
        return sorted(folders)
    
    def _process_folder(self, folder_path: str):
        """Process a single game folder"""
        folder_name = os.path.basename(folder_path)
        
        try:
            # Step 1: Analyze folder contents
            files_info = self.analyzer.get_files_in_folder(folder_path)
            
            if not files_info['all_files']:
                self.results['not_renamed'].append({
                    'folder': folder_name,
                    'reason': 'No files found in folder'
                })
                return
            
            # Step 2: Identify game using LLM
            identification = self.analyzer.identify_game(folder_name, files_info)
            
            if not identification or not identification.get('is_game'):
                self.results['not_renamed'].append({
                    'folder': folder_name,
                    'reason': 'Not identified as a game'
                })
                return
            
            # Step 3: Check if it's DLsite only
            if identification.get('platform') != 'dlsite':
                self.results['not_renamed'].append({
                    'folder': folder_name,
                    'reason': f"Platform is {identification.get('platform')}, not DLsite"
                })
                return
            
            game_name = identification.get('game_name')
            rj_number = identification.get('rj_number')
            
            logger.info(f"Identified: {game_name} (RJ: {rj_number}, Platform: {identification.get('platform')})")
            
            # Step 4: Search for the game on DLsite
            if not rj_number:
                search_results = self.searcher.search_dlsite(game_name)
                
                if search_results:
                    best_link = self.searcher.choose_link_with_llm(game_name, search_results)
                    
                    if best_link:
                        logger.info(f"Selected link: {best_link}")
                        
                        # Step 5: Scrape metadata from DLsite
                        metadata = self.scraper.extract_metadata(best_link)
                        
                        if metadata and metadata['valid']:
                            rj_number = metadata['rj_number']
                            game_name = metadata['game_name']
                            author = metadata.get('author')
                            release_date = metadata['release_date']
                        else:
                            self.results['not_renamed'].append({
                                'folder': folder_name,
                                'reason': 'Could not extract metadata from DLsite page'
                            })
                            return
                    else:
                        self.results['not_renamed'].append({
                            'folder': folder_name,
                            'reason': 'LLM could not choose correct link'
                        })
                        return
                else:
                    self.results['not_renamed'].append({
                        'folder': folder_name,
                        'reason': 'No search results found'
                    })
                    return
            else:
                # Already have RJ number, initialize author as None
                author = None
                release_date = None
            
            # Step 6: Rename folder
            if not rj_number or not game_name:
                self.results['not_renamed'].append({
                    'folder': folder_name,
                    'reason': 'Missing RJ number or game name for rename'
                })
                return
            
            # Format: [YYMMDD][RJ number][Author]Game name
            # Use today's date if release date not found
            date_str = release_date if release_date else datetime.now().strftime('%Y%m%d')
            
            # Clean game name for folder name (remove special characters)
            safe_name = re.sub(r'[<>:"/\\|?*]', '', game_name).strip()
            
            # Build folder name with author if available
            if author:
                safe_author = re.sub(r'[<>:"/\\|?*]', '', author).strip()
                new_folder_name = f"[{date_str}][{rj_number}][{safe_author}]{safe_name}"
            else:
                new_folder_name = f"[{date_str}][{rj_number}]{safe_name}"
            
            new_folder_path = os.path.join(os.path.dirname(folder_path), new_folder_name)
            
            # Avoid overwriting existing folders
            if os.path.exists(new_folder_path):
                new_folder_name = f"{new_folder_name}_{datetime.now().strftime('%H%M%S')}"
                new_folder_path = os.path.join(os.path.dirname(folder_path), new_folder_name)
            
            # Perform rename
            try:
                os.rename(folder_path, new_folder_path)
                logger.info(f"Renamed to: {new_folder_name}")
                
                self.results['renamed'].append({
                    'original': folder_name,
                    'new_name': new_folder_name,
                    'game_name': game_name,
                    'author': author,
                    'rj_number': rj_number,
                    'release_date': release_date
                })
            except Exception as e:
                logger.error(f"Failed to rename: {e}")
                self.results['not_renamed'].append({
                    'folder': folder_name,
                    'reason': f'Rename failed: {str(e)}'
                })
        
        except Exception as e:
            logger.error(f"Error processing folder {folder_name}: {e}")
            self.results['errors'].append({
                'folder': folder_name,
                'error': str(e)
            })
    
    def _save_results(self):
        """Save results to JSON file"""
        output_file = os.path.join(self.root_folder, 'rename_results.json')
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, ensure_ascii=False, indent=2)
            logger.info(f"Results saved to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
    
    def _print_summary(self):
        """Print summary of results"""
        print("\n" + "="*60)
        print("GAME RENAMING SUMMARY")
        print("="*60)
        
        print(f"\nSuccessfully Renamed: {len(self.results['renamed'])}")
        for item in self.results['renamed']:
            print(f"  {item['original']}")
            print(f"    → {item['new_name']}")
        
        print(f"\nNot Renamed: {len(self.results['not_renamed'])}")
        for item in self.results['not_renamed']:
            print(f"  {item['folder']}: {item['reason']}")
        
        if self.results['errors']:
            print(f"\nErrors: {len(self.results['errors'])}")
            for item in self.results['errors']:
                print(f"  {item['folder']}: {item['error']}")
        
        print("\n" + "="*60)


def main():
    """Main entry point"""
    
    # Configuration
    root_folder = r"c:\Users\Megu\Desktop\HTools"
    
    # Default target folder for game folders
    # Change this to scan a specific subfolder for games
    target_folder = root_folder
    
    try:
        renamer = GameRenamer(target_folder)
        renamer.run()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
