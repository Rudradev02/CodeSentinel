"""Safe configuration file loader for CodeSentinel (.codesentinel.yml / .codesentinel.json)."""

import json
from pathlib import Path
from typing import Optional

from pydantic import ValidationError
from analyzer.config.repo_config import RepoConfig


class ConfigLoadError(Exception):
    """Exception raised when repository configuration fails to load or validate."""
    pass


def load_repo_config(
    target_dir: Path | str,
    explicit_config_path: Optional[Path | str] = None,
) -> tuple[RepoConfig, Optional[Path], str]:
    """Discover, load, and validate repository configuration.
    
    Args:
        target_dir: Root directory of the repository being analyzed.
        explicit_config_path: Optional explicit file path to configuration file (--config).
        
    Returns:
        tuple of (validated RepoConfig, discovered Path or None, config_hash string).
        
    Raises:
        ConfigLoadError: If explicit config path does not exist, syntax is invalid, or schema validation fails.
    """
    target_path = Path(target_dir).resolve()
    config_file: Optional[Path] = None

    if explicit_config_path is not None:
        explicit_file = Path(explicit_config_path).resolve()
        if not explicit_file.is_file():
            raise ConfigLoadError(f"Specified configuration file does not exist: {explicit_file}")
        config_file = explicit_file
    else:
        # Check standard default filenames
        for candidate in [".codesentinel.yml", ".codesentinel.yaml", ".codesentinel.json"]:
            candidate_path = target_path / candidate
            if candidate_path.is_file():
                config_file = candidate_path
                break

    if config_file is None:
        default_config = RepoConfig()
        return default_config, None, default_config.compute_hash()

    try:
        content = config_file.read_text(encoding="utf-8")
    except Exception as e:
        raise ConfigLoadError(f"Failed to read configuration file at '{config_file}': {e}") from e

    raw_data = None
    if config_file.suffix.lower() == ".json":
        try:
            raw_data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ConfigLoadError(f"Invalid JSON syntax in '{config_file}': {e}") from e
    else:
        try:
            import yaml
            raw_data = yaml.safe_load(content)
        except ImportError:
            raise ConfigLoadError(
                f"PyYAML is required to parse '{config_file}'. Please install 'pyyaml' or provide a '.codesentinel.json' file instead."
            )
        except Exception as e:
            raise ConfigLoadError(f"Invalid YAML syntax in '{config_file}': {e}") from e

    if raw_data is None:
        # Empty file returns default configuration
        raw_data = {}
    elif not isinstance(raw_data, dict):
        raise ConfigLoadError(f"Configuration file '{config_file}' must contain a YAML/JSON mapping, got {type(raw_data).__name__}.")

    try:
        config = RepoConfig.model_validate(raw_data)
    except ValidationError as e:
        # Format actionable validation error
        errors = []
        for err in e.errors():
            loc = ".".join(str(x) for x in err["loc"])
            msg = err["msg"]
            errors.append(f"  - [{loc}]: {msg}")
        err_msg = "\n".join(errors)
        raise ConfigLoadError(f"Configuration validation failed in '{config_file}':\n{err_msg}") from e

    config_hash = config.compute_hash()
    return config, config_file, config_hash
