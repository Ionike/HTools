#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Quick test script for SteamDB search"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(__file__))

import logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

from game_renamer import SearchPlatform, MultiPlatformSearcher, LMStudioClient, PlatformScraper

def main():
    folder_name = 'Academy Love Saga Tennis Angels EX'
    print(f'Testing with folder: {folder_name}')
    print('='*60)

    # Initialize LLM
    print('Checking LMStudio connection...')
    llm = LMStudioClient()
    if not llm.check_connection():
        print('ERROR: LMStudio not running!')
        sys.exit(1)
    print('LMStudio OK')

    # Initialize searcher
    platforms = {SearchPlatform.STEAMDB}
    searcher = MultiPlatformSearcher(llm, platforms)

    # Search with non-headless mode
    print('\nSearching (non-headless mode)...')
    # Override driver init to use non-headless
    if searcher._init_driver(headless=False, use_proxy=False):
        print('Driver initialized in visible mode')

    result = searcher.search_game(folder_name)
    print(f'\nSearch result:')
    print(f'  is_found: {result.is_found}')
    print(f'  platform: {result.platform}')
    print(f'  product_id: {result.product_id}')
    print(f'  confidence: {result.confidence}')

    if result.is_found and result.product_id:
        print('\nScraping metadata...')
        scraper = PlatformScraper()
        metadata = scraper.scrape_steam(result.product_id)
        if metadata:
            print(f'  game_name: {metadata.get("game_name")}')
            print(f'  author: {metadata.get("author")}')
            print(f'  release_date: {metadata.get("release_date")}')
        else:
            print('  Failed to scrape metadata')

    print('\nDone')

if __name__ == '__main__':
    main()
