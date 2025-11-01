#!/usr/bin/env python3
"""
Configuration Manager for BugHunter Pro
Handles YAML configs, environment variables, and CLI arguments
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class ScannerConfig:
    """Scanner configuration"""
    # Target settings
    target_url: str = ""
    max_depth: int = 3
    max_pages: int = 100
    follow_redirects: bool = True
    
    # Performance settings
    threads: int = 50
    timeout: int = 30
    delay: float = 0.1
    rate_limit: float = 100.0
    
    # Async settings
    async_enabled: bool = True
    async_pool_size: int = 100
    
    # Scanner settings
    enable_ml: bool = False
    enable_evasion: bool = False
    enable_compliance: bool = False
    enable_headless: bool = False
    
    # Categories to scan
    scan_categories: list = field(default_factory=lambda: [
        'injection', 'xss', 'auth', 'config', 'api'
    ])
    
    # Output settings
    output_dir: str = "output"
    report_formats: list = field(default_factory=lambda: ['json', 'html'])
    verbose: bool = False
    
    # Database settings
    database_path: str = "database/cve_database.db"
    enable_cve_sync: bool = False
    
    # API settings
    nvd_api_key: Optional[str] = None
    github_token: Optional[str] = None
    
    # Security settings
    verify_ssl: bool = False
    user_agent: str = "BugHunter Pro/7.0"
    
    # Plugin settings
    plugin_dirs: list = field(default_factory=lambda: ['plugins'])
    enabled_plugins: list = field(default_factory=list)
    disabled_plugins: list = field(default_factory=list)


class ConfigManager:
    """Manages application configuration"""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_file: Path to YAML config file (optional)
        """
        self.config_file = config_file
        self.config = ScannerConfig()
        self._config_loaded = False
        
        # Load configuration
        self._load_config()
    
    def _load_config(self):
        """Load configuration from multiple sources"""
        # 1. Load from YAML file if provided
        if self.config_file and Path(self.config_file).exists():
            self._load_from_yaml(self.config_file)
        
        # 2. Load from environment variables
        self._load_from_env()
        
        # 3. Load from default config file if exists
        default_config = Path("config.yaml")
        if default_config.exists() and not self._config_loaded:
            self._load_from_yaml(str(default_config))
        
        logger.info("Configuration loaded successfully")
    
    def _load_from_yaml(self, config_file: str):
        """
        Load configuration from YAML file
        
        Args:
            config_file: Path to YAML file
        """
        try:
            with open(config_file, 'r') as f:
                data = yaml.safe_load(f)
            
            if data:
                self._update_config(data)
                self._config_loaded = True
                logger.info(f"Loaded configuration from: {config_file}")
        
        except Exception as e:
            logger.error(f"Failed to load config from {config_file}: {e}")
    
    def _load_from_env(self):
        """Load configuration from environment variables"""
        env_mapping = {
            'BUGHUNTER_TARGET': 'target_url',
            'BUGHUNTER_THREADS': ('threads', int),
            'BUGHUNTER_TIMEOUT': ('timeout', int),
            'BUGHUNTER_DELAY': ('delay', float),
            'BUGHUNTER_MAX_DEPTH': ('max_depth', int),
            'BUGHUNTER_MAX_PAGES': ('max_pages', int),
            'BUGHUNTER_VERBOSE': ('verbose', bool),
            'BUGHUNTER_OUTPUT_DIR': 'output_dir',
            'BUGHUNTER_NVD_API_KEY': 'nvd_api_key',
            'BUGHUNTER_GITHUB_TOKEN': 'github_token',
            'BUGHUNTER_ENABLE_ML': ('enable_ml', bool),
            'BUGHUNTER_ENABLE_EVASION': ('enable_evasion', bool),
            'BUGHUNTER_ENABLE_CVE_SYNC': ('enable_cve_sync', bool),
        }
        
        for env_var, config_key in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                # Handle type conversion
                if isinstance(config_key, tuple):
                    config_key, converter = config_key
                    try:
                        if converter == bool:
                            value = value.lower() in ('true', '1', 'yes')
                        else:
                            value = converter(value)
                    except ValueError:
                        logger.warning(f"Invalid value for {env_var}: {value}")
                        continue
                
                setattr(self.config, config_key, value)
                logger.debug(f"Set {config_key} from environment: {value}")
    
    def _update_config(self, data: Dict[str, Any]):
        """
        Update configuration from dictionary
        
        Args:
            data: Configuration dictionary
        """
        for key, value in data.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
            else:
                logger.warning(f"Unknown config key: {key}")
    
    def update_from_args(self, args: Dict[str, Any]):
        """
        Update configuration from CLI arguments
        
        Args:
            args: Argument dictionary from argparse
        """
        for key, value in args.items():
            if value is not None and hasattr(self.config, key):
                setattr(self.config, key, value)
                logger.debug(f"Updated {key} from CLI: {value}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value
        
        Args:
            key: Configuration key
            default: Default value if not found
        
        Returns:
            Configuration value
        """
        return getattr(self.config, key, default)
    
    def set(self, key: str, value: Any):
        """
        Set configuration value
        
        Args:
            key: Configuration key
            value: Value to set
        """
        if hasattr(self.config, key):
            setattr(self.config, key, value)
            logger.debug(f"Set {key} = {value}")
        else:
            logger.warning(f"Unknown config key: {key}")
    
    def save_to_yaml(self, filename: str):
        """
        Save configuration to YAML file
        
        Args:
            filename: Output filename
        """
        try:
            data = asdict(self.config)
            
            with open(filename, 'w') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            
            logger.info(f"Configuration saved to: {filename}")
        
        except Exception as e:
            logger.error(f"Failed to save config to {filename}: {e}")
    
    def validate(self) -> bool:
        """
        Validate configuration
        
        Returns:
            True if configuration is valid
        """
        errors = []
        
        # Validate required fields
        if not self.config.target_url and self._config_loaded:
            errors.append("target_url is required")
        
        # Validate numeric ranges
        if self.config.threads < 1:
            errors.append("threads must be >= 1")
        
        if self.config.timeout < 1:
            errors.append("timeout must be >= 1")
        
        if self.config.delay < 0:
            errors.append("delay must be >= 0")
        
        if self.config.max_depth < 1:
            errors.append("max_depth must be >= 1")
        
        if self.config.max_pages < 1:
            errors.append("max_pages must be >= 1")
        
        # Validate paths
        output_dir = Path(self.config.output_dir)
        if not output_dir.exists():
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create output directory: {e}")
        
        if errors:
            for error in errors:
                logger.error(f"Configuration error: {error}")
            return False
        
        return True
    
    def print_config(self):
        """Print current configuration"""
        print("\n" + "="*60)
        print("BugHunter Pro Configuration")
        print("="*60)
        
        config_dict = asdict(self.config)
        
        for key, value in config_dict.items():
            # Mask sensitive values
            if 'key' in key.lower() or 'token' in key.lower():
                if value:
                    value = '***' + str(value)[-4:] if len(str(value)) > 4 else '****'
            
            print(f"{key:25} : {value}")
        
        print("="*60 + "\n")
    
    def get_config_dict(self) -> Dict[str, Any]:
        """
        Get configuration as dictionary
        
        Returns:
            Configuration dictionary
        """
        return asdict(self.config)


def create_default_config(filename: str = "config.yaml"):
    """
    Create a default configuration file
    
    Args:
        filename: Output filename
    """
    default_config = {
        'target_url': 'http://example.com',
        'max_depth': 3,
        'max_pages': 100,
        'threads': 50,
        'timeout': 30,
        'delay': 0.1,
        'rate_limit': 100.0,
        'async_enabled': True,
        'async_pool_size': 100,
        'enable_ml': False,
        'enable_evasion': False,
        'enable_compliance': False,
        'enable_headless': False,
        'scan_categories': ['injection', 'xss', 'auth', 'config', 'api'],
        'output_dir': 'output',
        'report_formats': ['json', 'html'],
        'verbose': False,
        'database_path': 'database/cve_database.db',
        'enable_cve_sync': False,
        'nvd_api_key': None,
        'github_token': None,
        'verify_ssl': False,
        'user_agent': 'BugHunter Pro/7.0',
        'plugin_dirs': ['plugins'],
        'enabled_plugins': [],
        'disabled_plugins': []
    }
    
    try:
        with open(filename, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)
        
        print(f"✅ Created default configuration: {filename}")
    
    except Exception as e:
        print(f"❌ Failed to create config file: {e}")


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Create default config
    create_default_config("example_config.yaml")
    
    # Load and validate config
    config_manager = ConfigManager("example_config.yaml")
    
    # Print config
    config_manager.print_config()
    
    # Validate
    if config_manager.validate():
        print("✅ Configuration is valid")
    else:
        print("❌ Configuration has errors")
