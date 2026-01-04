"""Load and process analysis rules from YAML configuration."""

import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional


def load_analysis_rules() -> Dict[str, List[Dict[str, Any]]]:
    """
    Load security analysis rules from YAML file.

    Returns:
        Dict mapping analyzer name to list of rules
    """
    rules_file = Path(__file__).parent.parent / "data" / "analysis_rules.yaml"

    try:
        with open(rules_file) as f:
            rules = yaml.safe_load(f)
            return rules or {}
    except (FileNotFoundError, yaml.YAMLError) as e:
        # Fallback to empty rules if file not found or invalid
        import warnings

        warnings.warn(f"Could not load analysis rules: {e}")
        return {}


def get_rules_for_analyzer(analyzer_name: str) -> List[Dict[str, Any]]:
    """
    Get rules for specific analyzer.

    Args:
        analyzer_name: Name of the analyzer

    Returns:
        List of rules for the analyzer
    """
    all_rules = load_analysis_rules()
    return all_rules.get(analyzer_name, [])


def convert_rule_to_legacy_format(
    analyzer_name: str, rule: Dict[str, Any], analyzer_data: Optional[Dict[str, Any]]
) -> tuple:
    """
    Convert YAML rule to legacy tuple format for backward compatibility.

    Args:
        analyzer_name: Name of analyzer
        rule: Rule dict from YAML
        analyzer_data: Analyzer result data

    Returns:
        Tuple: (analyzer_data, conditions, message, category)
    """
    conditions = rule["conditions"]
    message = rule["message"]
    category = rule["category"]

    return (analyzer_data, conditions, message, category)
