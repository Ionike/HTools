#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web UI to view FANZA/SteamDB game_renamer results and reverse renames
Real-time updates supported!
"""

import os
import json
import sys
import argparse
from flask import Flask, render_template, jsonify, request
import logging

# Force UTF-8 encoding for console output
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration - will be set dynamically
PARENT_FOLDER = None
RESULTS_FILE = None


def set_working_directory(folder_path):
    """Set the working directory for the viewer"""
    global PARENT_FOLDER, RESULTS_FILE
    PARENT_FOLDER = folder_path
    RESULTS_FILE = os.path.join(PARENT_FOLDER, 'rename_results.json')


def load_results():
    """Load rename results from JSON file"""
    try:
        if not os.path.exists(RESULTS_FILE):
            return {'renamed': [], 'moved_unidentified': [], 'skipped': [], 'errors': []}

        with open(RESULTS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load results: {e}")
        return {'renamed': [], 'moved_unidentified': [], 'skipped': [], 'errors': []}


def save_results(results):
    """Save results back to JSON file"""
    try:
        with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
        return False


def get_platform_link(item):
    """Generate platform-specific link"""
    platform = item.get('platform', '')
    product_id = item.get('product_id', '')
    url = item.get('url', '')

    if url:
        return url

    if platform == 'fanza':
        return f"https://www.dmm.co.jp/mono/pcgame/-/detail/=/cid={product_id}/"
    elif platform == 'steam':
        return f"https://store.steampowered.com/app/{product_id}"

    return ""


@app.route('/')
def index():
    """Main page showing all rename results"""
    results = load_results()

    # Build display data with platform links
    renamed_data = []
    for item in results.get('renamed', []):
        platform_link = get_platform_link(item)

        renamed_data.append({
            'original': item.get('original', ''),
            'new_name': item.get('new_name', ''),
            'platform_link': platform_link,
            'product_id': item.get('product_id', ''),
            'game_name': item.get('game_name', ''),
            'author': item.get('author', ''),
            'release_date': item.get('release_date', ''),
            'platform': item.get('platform', 'unknown')
        })

    return render_template('rename_viewer.html',
                         renamed=renamed_data,
                         total=len(renamed_data))


@app.route('/reverse', methods=['POST'])
def reverse_rename():
    """Reverse a single folder rename"""
    data = request.get_json()
    original_name = data.get('original')
    new_name = data.get('new_name')

    if not original_name or not new_name:
        return jsonify({'success': False, 'error': 'Missing folder names'})

    new_path = os.path.join(PARENT_FOLDER, new_name)
    original_path = os.path.join(PARENT_FOLDER, original_name)

    if not os.path.exists(new_path):
        return jsonify({'success': False, 'error': f'Folder not found: {new_name}'})

    if os.path.exists(original_path):
        return jsonify({'success': False, 'error': f'Original name already exists: {original_name}'})

    try:
        os.rename(new_path, original_path)
        logger.info(f"Reversed rename: {new_name} -> {original_name}")

        results = load_results()
        results['renamed'] = [item for item in results['renamed']
                             if item.get('new_name') != new_name]

        results['skipped'].append({
            'folder': original_name,
            'reason': 'Reversed by user'
        })

        save_results(results)

        return jsonify({'success': True})

    except Exception as e:
        logger.error(f"Failed to reverse rename: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/open_folder', methods=['POST'])
def open_folder():
    """Open folder in file explorer"""
    import subprocess

    data = request.get_json()
    folder_name = data.get('folder_name')

    if not folder_name:
        return jsonify({'success': False, 'error': 'Missing folder name'})

    folder_path = os.path.join(PARENT_FOLDER, folder_name)

    if not os.path.exists(folder_path):
        return jsonify({'success': False, 'error': f'Folder not found: {folder_name}'})

    try:
        if sys.platform == 'win32':
            os.startfile(folder_path)
        elif sys.platform == 'darwin':
            subprocess.Popen(['open', folder_path])
        else:
            subprocess.Popen(['xdg-open', folder_path])

        logger.info(f"Opened folder: {folder_path}")
        return jsonify({'success': True})

    except Exception as e:
        logger.error(f"Failed to open folder: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/stats')
def get_stats():
    """Get summary statistics"""
    results = load_results()
    return jsonify({
        'renamed': len(results.get('renamed', [])),
        'moved_unidentified': len(results.get('moved_unidentified', [])),
        'skipped': len(results.get('skipped', [])),
        'errors': len(results.get('errors', []))
    })


@app.route('/api/data')
def get_all_data():
    """Get all data for real-time updates"""
    results = load_results()

    renamed_data = []
    for item in results.get('renamed', []):
        platform_link = get_platform_link(item)
        renamed_data.append({
            'original': item.get('original', ''),
            'new_name': item.get('new_name', ''),
            'platform_link': platform_link,
            'product_id': item.get('product_id', ''),
            'game_name': item.get('game_name', ''),
            'author': item.get('author', ''),
            'release_date': item.get('release_date', ''),
            'platform': item.get('platform', 'unknown')
        })

    return jsonify({
        'renamed': renamed_data,
        'errors': results.get('errors', []),
        'moved_unidentified': results.get('moved_unidentified', []),
        'skipped': results.get('skipped', []),
        'stats': {
            'renamed': len(renamed_data),
            'errors': len(results.get('errors', [])),
            'moved_unidentified': len(results.get('moved_unidentified', [])),
            'skipped': len(results.get('skipped', []))
        }
    })


def start_viewer(parent_folder, port=5001, debug=False):
    """Start the viewer with specified folder"""
    set_working_directory(parent_folder)

    print("="*60)
    print("FANZA/SteamDB Game Renamer Results Viewer")
    print("="*60)
    print(f"Results file: {RESULTS_FILE}")
    print(f"Parent folder: {PARENT_FOLDER}")
    print(f"\nStarting web server at http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop")
    print("="*60)

    app.run(debug=debug, host='127.0.0.1', port=port, use_reloader=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='View game renamer results in a web interface')
    parser.add_argument(
        'parent_folder',
        type=str,
        nargs='?',
        help='Path to the parent folder'
    )
    parser.add_argument('--port', type=int, default=5001, help='Port to run the server on')

    args = parser.parse_args()

    if args.parent_folder:
        parent_folder = args.parent_folder
    else:
        parent_folder = input("Enter the path to the folder: ").strip().strip('"').strip("'")

    if not os.path.exists(parent_folder):
        print(f"Error: Directory '{parent_folder}' does not exist")
        sys.exit(1)

    start_viewer(parent_folder, port=args.port, debug=True)
