#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration module for Game Folder Renamer
Handles settings, paths, and configurations
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

# Root path configuration
ROOT_PATH = Path(__file__).parent.parent.absolute()
CONFIG_FILE = Path(__file__).parent / "config_game_renamer.json"
LOG_FILE = Path(__file__).parent / "game_renamer.log"

# Default configuration
DEFAULT_CONFIG = {
    "game_folder_path": str(ROOT_PATH),
    "lm_studio_config": {
        "host": "localhost",
        "port": 1234,
        "timeout": 30
    },
    "dlsite_config": {
        "search_timeout": 15,
        "use_proxy": True,
        "max_retries": 3
    },
    "naming_format": {
        "format": "[YYMMDD][RJ########][Author]Game Name",
        "examples": [
            "[250125][RJ01023407][Topyu_u]紫森リチュアル",
            "[250110][RJ00123456]Game Title"
        ],
        "date_source": "dlsite_release_date",  # or "current_date"
        "clean_special_chars": True,
        "max_folder_name_length": 255
    },
    "logging_config": {
        "level": "INFO",
        "format": "%(asctime)s - %(levelname)s - %(message)s",
        "file_output": True,
        "console_output": True
    },
    "performance": {
        "max_folders_per_run": None,  # None = unlimited
        "rate_limit_delay": 1.0,  # seconds between requests
        "check_existing_before_rename": True
    }
}


class ConfigManager:
    """Manages configuration for the game renamer"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize config manager"""
        self.config_path = Path(config_path) if config_path else CONFIG_FILE
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file or use defaults"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults to fill missing keys
                    return {**DEFAULT_CONFIG, **loaded_config}
            except Exception as e:
                print(f"Warning: Could not load config file: {e}")
                print("Using default configuration")
                return DEFAULT_CONFIG
        else:
            # Create default config file
            self.save_config()
            return DEFAULT_CONFIG
    
    def save_config(self):
        """Save current configuration to JSON file"""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
            print(f"Configuration saved to: {self.config_path}")
        except Exception as e:
            print(f"Error saving configuration: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key (supports dot notation)"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        
        return value if value is not None else default
    
    def set(self, key: str, value: Any):
        """Set a configuration value by key (supports dot notation)"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary"""
        return self.config.copy()


def get_game_folder_path() -> Path:
    """Get the root game folder path"""
    config = ConfigManager()
    path = config.get('game_folder_path')
    return Path(path) if path else ROOT_PATH


def get_naming_format() -> str:
    """Get the naming format template"""
    config = ConfigManager()
    return config.get('naming_format.format')


def get_lm_studio_config() -> Dict[str, Any]:
    """Get LMStudio configuration"""
    config = ConfigManager()
    return config.get('lm_studio_config', DEFAULT_CONFIG['lm_studio_config'])


def get_dlsite_config() -> Dict[str, Any]:
    """Get DLsite search configuration"""
    config = ConfigManager()
    return config.get('dlsite_config', DEFAULT_CONFIG['dlsite_config'])


if __name__ == "__main__":
    # Example usage
    config = ConfigManager()
    
    print("Current Configuration:")
    print(json.dumps(config.to_dict(), ensure_ascii=False, indent=2))
    
    print("\nExample queries:")
    print(f"Game folder path: {config.get('game_folder_path')}")
    print(f"LMStudio host: {config.get('lm_studio_config.host')}")
    print(f"Naming format: {config.get('naming_format.format')}")
