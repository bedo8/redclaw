"""Built-in campaign definitions and the campaign loader.

The YAML files in this package ship inside the wheel and are read through
:mod:`importlib.resources`, so ``redclaw scan --campaign <name>`` works from
any install, not just a source checkout.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from redclaw.config import CampaignConfig

_YAML_SUFFIXES = (".yaml", ".yml")


class CampaignNotFoundError(LookupError):
    """Raised when a campaign name or path cannot be resolved."""


class CampaignLoadError(ValueError):
    """Raised when a campaign file exists but is not a valid campaign."""


@dataclass(frozen=True)
class CampaignInfo:
    """Summary of an available campaign for listings."""

    key: str
    name: str
    description: str
    source: str  # "built-in" or a filesystem path


def _builtin_files() -> dict[str, Any]:
    root = resources.files(__name__)
    return {
        entry.name.rsplit(".", 1)[0]: entry
        for entry in root.iterdir()
        if entry.is_file() and entry.name.endswith(_YAML_SUFFIXES)
    }


def builtin_campaign_names() -> list[str]:
    """Names of the campaigns bundled with RedClaw."""
    return sorted(_builtin_files())


def parse_campaign(data: Any, source: str = "<memory>") -> CampaignConfig:
    """Validate a parsed YAML mapping as a campaign."""
    if not isinstance(data, dict):
        raise CampaignLoadError(f"{source}: campaign must be a YAML mapping")
    try:
        campaign = CampaignConfig.model_validate(data)
    except ValidationError as exc:
        raise CampaignLoadError(f"{source}: invalid campaign definition\n{exc}") from exc

    from redclaw.core.scheduler import registered_module_ids

    known = set(registered_module_ids())
    unknown = sorted({m for p in campaign.phases for m in p.attack_modules} - known)
    if unknown:
        raise CampaignLoadError(
            f"{source}: unknown attack module(s) {unknown}. Available: {sorted(known)}"
        )
    return campaign


def load_campaign_file(path: str | Path) -> CampaignConfig:
    """Load and validate a campaign from a YAML file on disk."""
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CampaignLoadError(f"{path}: invalid YAML: {exc}") from exc
    return parse_campaign(data, str(path))


def load_builtin_campaign(name: str) -> CampaignConfig:
    """Load a bundled campaign by name (file stem)."""
    files = _builtin_files()
    if name not in files:
        raise CampaignNotFoundError(name)
    data = yaml.safe_load(files[name].read_text(encoding="utf-8"))
    return parse_campaign(data, f"built-in:{name}")


def resolve_campaign(name_or_path: str, search_dirs: list[Path] | None = None) -> CampaignConfig:
    """Resolve a campaign reference to a validated :class:`CampaignConfig`.

    Resolution order:

    1. An existing ``.yaml``/``.yml`` file path.
    2. ``<dir>/<name>.yaml`` in each of ``search_dirs`` (default: ``./campaigns``),
       so project-local campaigns can shadow built-ins.
    3. A built-in campaign with that name.

    Raises:
        CampaignNotFoundError: nothing matched. Unknown names are an error,
            never a silent fallback to a default campaign.
    """
    direct = Path(name_or_path)
    if direct.suffix in _YAML_SUFFIXES:
        if direct.is_file():
            return load_campaign_file(direct)
        raise CampaignNotFoundError(f"campaign file not found: {name_or_path}")

    for directory in search_dirs if search_dirs is not None else [Path.cwd() / "campaigns"]:
        for suffix in _YAML_SUFFIXES:
            candidate = directory / f"{name_or_path}{suffix}"
            if candidate.is_file():
                return load_campaign_file(candidate)

    try:
        return load_builtin_campaign(name_or_path)
    except CampaignNotFoundError:
        available = ", ".join(builtin_campaign_names())
        raise CampaignNotFoundError(
            f"unknown campaign '{name_or_path}'. Built-in campaigns: {available}. "
            "Pass a path to a .yaml file to use a custom campaign."
        ) from None


def list_campaigns(search_dirs: list[Path] | None = None) -> list[CampaignInfo]:
    """List built-in campaigns plus any YAML campaigns in ``search_dirs``."""
    infos: list[CampaignInfo] = []
    for key in builtin_campaign_names():
        cfg = load_builtin_campaign(key)
        infos.append(CampaignInfo(key, cfg.name, cfg.description.strip(), "built-in"))

    for directory in search_dirs if search_dirs is not None else [Path.cwd() / "campaigns"]:
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if path.suffix not in _YAML_SUFFIXES:
                continue
            try:
                cfg = load_campaign_file(path)
            except CampaignLoadError:
                continue
            infos.append(CampaignInfo(path.stem, cfg.name, cfg.description.strip(), str(path)))
    return infos


__all__ = [
    "CampaignInfo",
    "CampaignLoadError",
    "CampaignNotFoundError",
    "builtin_campaign_names",
    "list_campaigns",
    "load_builtin_campaign",
    "load_campaign_file",
    "parse_campaign",
    "resolve_campaign",
]
