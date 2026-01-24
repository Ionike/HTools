# Generate ComicInfo.xml for EhViewer from https://sleazyfork.org/en/scripts/10379-e-hentai-downloader's info.txt
# Rename images in the folder to %08d format
import os
import re
import sys
import shutil
from pathlib import Path
from xml.etree.ElementTree import Element, ElementTree

# Configuration - Set your gallery parent directory here
GALLERY_PARENT_DIR = Path("D:\\Manga\\同人")
ERROR_LOG_FILE = "\error_log.txt"
ERROR_GALLERIES_FOLDER = "ERROR_GALLERIES"

# Gallery link pattern: https://exhentai.org/g/{numbers}/{alphanumeric}/
GALLERY_LINK_PATTERN = r'https://exhentai\.org/g/\d+/[a-f0-9]+/'

def find_main_gallery_link(info_txt_path):
    """Extract the main gallery link from info.txt"""
    try:
        with open(info_txt_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find all matches of the gallery link pattern
        matches = re.findall(GALLERY_LINK_PATTERN, content)
        
        if matches:
            # Return the first match (the main gallery link)
            return matches[0]
        else:
            return None
    except Exception as e:
        raise Exception(f"Error reading info.txt: {str(e)}")

def create_comic_info_xml(gallery_link, output_path):
    """Generate ComicInfo.xml file"""
    try:
        # Create root element
        root = Element('ComicInfo')
        root.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        root.set('xsi:noNamespaceSchemaLocation', 
                'https://raw.githubusercontent.com/anansi-project/comicinfo/main/schema/v2.0/ComicInfo.xsd')
        
        # Add Web element
        web_element = Element('Web')
        web_element.text = gallery_link
        root.append(web_element)
        
        # Write to file
        tree = ElementTree(root)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)
        
    except Exception as e:
        raise Exception(f"Error creating ComicInfo.xml: {str(e)}")

def rename_images_in_folder(folder_path):
    """Rename all images in folder to %08d format preserving extensions"""
    errors = []
    renamed_count = 0
    
    try:
        # Get all files in folder, exclude info.txt and ComicInfo.xml
        files = [f for f in folder_path.iterdir() if f.is_file() 
                 and f.name not in ['info.txt', 'ComicInfo.xml']]
        
        # Sort files by name
        files.sort(key=lambda x: x.name)
        
        if not files:
            return renamed_count, errors
        
        # Rename each file with %08d format
        for index, file_path in enumerate(files, start=1):
            try:
                # Get file extension
                extension = file_path.suffix
                # Create new name with %08d format
                new_name = f"{index:08d}{extension}"
                new_path = folder_path / new_name
                
                # Rename the file
                file_path.rename(new_path)
                renamed_count += 1
                
            except Exception as e:
                error_msg = f"[{folder_path.name}] Failed to rename {file_path.name}: {str(e)}"
                errors.append(error_msg)
        
        return renamed_count, errors
        
    except Exception as e:
        error_msg = f"[{folder_path.name}] Error processing images: {str(e)}"
        errors.append(error_msg)
        return renamed_count, errors

def process_gallery_folders():
    """Process all gallery folders and generate ComicInfo.xml, rename images"""
    errors = []
    error_galleries = []  # Track galleries with errors
    processed_count = 0
    total_renamed = 0
    
    # Iterate through folders in the parent directory
    for folder_path in GALLERY_PARENT_DIR.iterdir():
        if not folder_path.is_dir():
            continue
        
        info_txt_path = folder_path / "info.txt"
        comic_info_path = folder_path / "ComicInfo.xml"
        has_error = False
        
        # Check if info.txt exists
        if not info_txt_path.exists():
            error_msg = f"[{folder_path.name}] info.txt not found"
            errors.append(error_msg)
            error_galleries.append(folder_path)
            print(f"ERROR: {error_msg}")
            continue
        
        # Extract gallery link
        try:
            gallery_link = find_main_gallery_link(info_txt_path)
            
            if not gallery_link:
                error_msg = f"[{folder_path.name}] Main gallery link not found in info.txt"
                errors.append(error_msg)
                error_galleries.append(folder_path)
                print(f"ERROR: {error_msg}")
                continue
            
            # Create ComicInfo.xml
            create_comic_info_xml(gallery_link, comic_info_path)
            print(f"SUCCESS: Generated ComicInfo.xml for {folder_path.name}")
            print(f"  Gallery Link: {gallery_link}")
            
            # Rename images in folder
            renamed_count, rename_errors = rename_images_in_folder(folder_path)
            if renamed_count > 0:
                print(f"  Renamed {renamed_count} images to %08d format")
            if rename_errors:
                has_error = True
                error_galleries.append(folder_path)
                errors.extend(rename_errors)
                for error in rename_errors:
                    print(f"  {error}")
            
            if not has_error:
                total_renamed += renamed_count
                processed_count += 1
            
        except Exception as e:
            error_msg = f"[{folder_path.name}] {str(e)}"
            errors.append(error_msg)
            error_galleries.append(folder_path)
            print(f"ERROR: {error_msg}")
    
    return processed_count, total_renamed, errors, error_galleries

def save_error_log(errors):
    """Save errors to a log file"""
    if errors:
        with open(ERROR_LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("Error Log\n")
            f.write("=" * 50 + "\n\n")
            for error in errors:
                f.write(f"{error}\n")
        print(f"\nErrors saved to {ERROR_LOG_FILE}")

def move_error_galleries(error_galleries):
    """Move galleries with errors to a separate folder for manual inspection"""
    if not error_galleries:
        return 0
    
    error_folder = GALLERY_PARENT_DIR / ERROR_GALLERIES_FOLDER
    
    try:
        # Create error folder if it doesn't exist
        error_folder.mkdir(exist_ok=True)
        
        moved_count = 0
        print(f"\nMoving error galleries to: {error_folder}")
        
        for gallery_path in error_galleries:
            try:
                destination = error_folder / gallery_path.name
                
                # If destination exists, add a suffix
                if destination.exists():
                    stem = gallery_path.name
                    counter = 1
                    while (error_folder / f"{stem}_{counter}").exists():
                        counter += 1
                    destination = error_folder / f"{stem}_{counter}"
                
                # Move the folder
                shutil.move(str(gallery_path), str(destination))
                print(f"  Moved: {gallery_path.name} -> {ERROR_GALLERIES_FOLDER}/")
                moved_count += 1
                
            except Exception as e:
                print(f"  ERROR moving {gallery_path.name}: {str(e)}")
        
        return moved_count
        
    except Exception as e:
        print(f"ERROR: Failed to create error folder: {str(e)}")
        return 0

def main():
    global GALLERY_PARENT_DIR
    
    # Allow passing folder path as command-line argument
    if len(sys.argv) > 1:
        GALLERY_PARENT_DIR = Path(sys.argv[1])
    
    print("Gallery ComicInfo.xml Generator & Image Renamer")
    print("=" * 50)
    print(f"Processing galleries in: {GALLERY_PARENT_DIR}")
    print(f"Folder exists: {GALLERY_PARENT_DIR.exists()}")
    print("=" * 50 + "\n")
    
    # List what folders are found
    if GALLERY_PARENT_DIR.exists():
        folders = [f for f in GALLERY_PARENT_DIR.iterdir() if f.is_dir()]
        print(f"Found {len(folders)} subdirectories:")
        for folder in folders:
            info_txt = folder / "info.txt"
            status = "✓ has info.txt" if info_txt.exists() else "✗ NO info.txt"
            print(f"  - {folder.name} ({status})")
        print()
    else:
        print("ERROR: Folder does not exist!")
        return
    
    processed_count, total_renamed, errors, error_galleries = process_gallery_folders()
    
    # Move error galleries to separate folder
    moved_count = move_error_galleries(error_galleries)
    
    print("\n" + "=" * 50)
    print(f"Processing Complete!")
    print(f"Successfully processed: {processed_count} galleries")
    print(f"Total images renamed: {total_renamed}")
    print(f"Galleries with errors: {len(error_galleries)}")
    print(f"Galleries moved to {ERROR_GALLERIES_FOLDER}: {moved_count}")
    
    if errors:
        save_error_log(errors)

if __name__ == "__main__":
    main()
