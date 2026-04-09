"""
Package detection heuristics for archives.

This module provides functionality to detect when an archive should be treated
as a package/installer rather than a collection of unrelated files.
"""

from __future__ import annotations

import logging
import os.path
from typing import TYPE_CHECKING, Optional

from sflock.abstracts import File as SFLockFile  # type: ignore

if TYPE_CHECKING:
    from .unpacker import ArchiveInfo


logger = logging.getLogger("karton.archive-extractor")


def _get_file_extension(filename: str) -> str:
    """Get file extension in lowercase"""
    _, ext = os.path.splitext(filename)
    return ext.lower()


def _classify_children(unpacked: SFLockFile) -> dict[str, list[str]]:
    """
    Classify children by file type.

    Returns:
        Dictionary with extensions as keys and lists of filenames as values
    """
    classified: dict[str, list[str]] = {}

    for child in unpacked.children:
        # Use relapath to preserve directory structure within archive
        # relapath contains the full relative path (e.g., "dir1/dir2/file.exe")
        child_name = (
            (child.relapath and child.relapath.decode("utf8"))
            or (child.filename and child.filename.decode("utf8"))
            or child.sha256
        )
        ext = _get_file_extension(child_name)

        if ext not in classified:
            classified[ext] = []
        classified[ext].append(child_name)

    return classified


def _is_known_installer_pattern(filename: str) -> bool:
    """Check if filename matches known installer patterns"""
    name_lower = filename.lower()

    installer_patterns = [
        "setup",
        "install",
        "installer",
        "launcher",
        "application",
        "updater",
        "patch",
        "hotfix",
    ]

    return any(pattern in name_lower for pattern in installer_patterns)


def _is_utility_executable(filename: str) -> bool:
    """Check if filename is a utility executable (not main app)"""
    name_lower = filename.lower()

    utility_patterns = [
        "unins",
        "uninstall",
        "unins000",
        "uninst",
        "update",
        "updater",
        "updater_",
        "patch",
        "hotfix",
        "checker",
        "verify",
        "verify_",
        "config",
        "configuration",
        "register",
        "registration",
        "repair",
        "fix_",
    ]

    return any(pattern in name_lower for pattern in utility_patterns)


def _get_executable_score(filename: str, size: int) -> tuple[int, str]:
    """
    Score an executable for likelihood of being the main application.

    Returns:
        Tuple of (score, reason) where higher is better
    """
    name_lower = filename.lower()
    score = 0
    reasons = []

    # High score for installer patterns
    if _is_known_installer_pattern(filename):
        score += 100
        reasons.append("installer_pattern")

    # Prefer setup.exe or install.exe
    if name_lower in ["setup.exe", "install.exe"]:
        score += 50
        reasons.append("setup_or_install")

    # Prefer main.exe or app.exe
    if name_lower in ["main.exe", "app.exe", "application.exe"]:
        score += 80
        reasons.append("main_app_name")

    # Penalize utility executables heavily
    if _is_utility_executable(filename):
        score -= 200
        reasons.append("utility")

    # Prefer larger files (likely the main app)
    if size > 1024 * 1024:  # > 1MB
        score += min(20, size // (1024 * 1024))  # Up to 20 points
        reasons.append("large")

    # Prefer executables in root (not in subdirectories)
    if "\\" not in name_lower and "/" not in name_lower:
        score += 10
        reasons.append("root_dir")

    # Electron app detection
    if name_lower == "electron.exe":
        score += 60
        reasons.append("electron")

    # Penalty for product/build metadata in filename
    product_patterns = ["product", "release", "build", "version"]
    if any(pattern in name_lower for pattern in product_patterns):
        score -= 10  # Slight penalty, likely not the main app
        reasons.append("product_meta")

    return score, ",".join(reasons)


def find_best_executable(unpacked: SFLockFile) -> Optional[str]:
    """
    Find the best executable to run from an archive using heuristics.

    Args:
        unpacked: The unpacked archive

    Returns:
        The filename of the best executable or None
    """
    classified = _classify_children(unpacked)
    executables = classified.get(".exe", [])

    if not executables:
        logger.info("No .exe files found in archive")
        return None

    if len(executables) == 1:
        executable = executables[0]
        logger.info(f"Single executable found: {executable}")
        return executable

    logger.info(f"Multiple executables found ({len(executables)}), scoring them...")

    # Score all executables
    scored_executables = []
    for child in unpacked.children:
        # Use relapath to preserve directory structure within archive
        child_name = (
            (child.relapath and child.relapath.decode("utf8"))
            or (child.filename and child.filename.decode("utf8"))
            or child.sha256
        )
        if child_name in executables:
            score, reason = _get_executable_score(child_name, child.filesize)
            scored_executables.append((score, child_name, reason, child.filesize))
            logger.debug(
                f"Scored {child_name}: {score} ({reason}) size={child.filesize}"
            )

    # Sort by score descending
    scored_executables.sort(key=lambda x: x[0], reverse=True)

    # Log top candidates
    for score, name, reason, size in scored_executables[:3]:
        logger.info(f"  {name}: score={score} reason={reason} size={size}")

    best = scored_executables[0]

    # Only use if score is reasonable (not negative)
    if best[0] < -50:
        logger.warning(
            f"Best scored executable has negative score ({best[0]}), "
            f"not treating as package"
        )
        return None

    logger.info(f"Selected executable: {best[1]} (score: {best[0]}, reason: {best[2]})")
    return best[1]


def _detect_electron_app(classified: dict[str, list[str]]) -> bool:
    """Detect if archive contains an Electron application"""
    all_files = []
    for files in classified.values():
        all_files.extend(files)

    all_names_lower = [f.lower() for f in all_files]

    electron_indicators = [
        "app.asar",
        "electron.exe",
        "package.json",
        "resources/app.asar",
        "resources/default_app.asar",
    ]

    matches = sum(
        1 for indicator in electron_indicators if indicator in all_names_lower
    )
    return matches >= 2


def _detect_installer_archive(classified: dict[str, list[str]]) -> tuple[bool, str]:
    """
    Detect if archive is an installer package.

    Returns:
        Tuple of (is_installer, reason)
    """
    exe_files = classified.get(".exe", [])
    dll_files = classified.get(".dll", [])

    # Single .exe with multiple .dlls - common pattern
    if len(exe_files) == 1 and len(dll_files) >= 2:
        return True, f"single exe with {len(dll_files)} dlls"

    # Multiple .exe with .dlls - likely installer
    if len(exe_files) >= 1 and len(dll_files) >= 3:
        return True, f"{len(exe_files)} exe with {len(dll_files)} dlls"

    # Check for installer patterns
    for exe in exe_files:
        if _is_known_installer_pattern(exe):
            return True, f"installer pattern in {exe}"

    return False, ""


def find_child_by_path(
    unpacked: SFLockFile,
    filepath: str,
) -> Optional[str]:
    """
    Find a child file matching the given filepath.

    Args:
        unpacked: The unpacked archive
        filepath: Relative path to file (e.g., "setup.exe" or "folder/file.exe")

    Returns:
        The matching child filename or None
    """
    target_path = filepath.strip()
    logger.info(f"Looking for executable: {target_path}")

    for child in unpacked.children:
        if child.relapath:
            try:
                child_path = child.relapath.decode("utf8")
                if child_path == target_path:
                    logger.info(f"Found match: {child_path}")
                    return child_path
            except UnicodeDecodeError:
                logger.warning(f"Failed to decode path {child.relapath} as utf8, skipping.")
                continue

    logger.warning(f"File not found in archive: {target_path}")
    return None


def determine_if_package(
    unpacked: SFLockFile,
    archive_info: "ArchiveInfo",
) -> None:
    """
    Determine if archive should be treated as a single package.
    Updates archive_info in-place with the decision.

    Args:
        unpacked: The unpacked archive
        archive_info: ArchiveInfo object to update with decision
    """
    logger.info("Checking if archive should be processed as a package")

    # If analyst provided a correct filepath, treat as package
    if archive_info.entry_path is not None:
        if find_child_by_path(unpacked, archive_info.entry_path):
            archive_info.is_package = True
            logger.info(
                f"Treating as package with selected executable: {archive_info.entry_path}"
                )
            return
        else:
            logger.warning(
                f"Analyst provided filepath '{archive_info.entry_path}' "
                "but file not found in archive. Falling back to heuristics."
            )
            archive_info.is_package = False

    # Automatic heuristics
    classified = _classify_children(unpacked)

    archive_contents = {ext: len(files) for ext, files in classified.items()}
    logger.info(f"Archive contents: {archive_contents}")

    # Detect Electron apps
    if _detect_electron_app(classified):
        logger.info("Detected Electron application")
        archive_info.is_package = True
        archive_info.entry_path = find_best_executable(unpacked)
        return

    # Detect installer archives
    is_installer, reason = _detect_installer_archive(classified)
    if is_installer:
        logger.info(f"Detected installer package: {reason}")
        archive_info.is_package = True
        archive_info.entry_path = find_best_executable(unpacked)
        return

    # Archive with exe file = package
    exe_files = classified.get(".exe", [])
    if len(exe_files) >= 1:
        logger.info("Archive contains exe file, treating as package")
        archive_info.is_package = True
        archive_info.entry_path = exe_files[0]
        return

    # No package detected
    logger.info("Archive does not match package patterns, extracting all children")
    archive_info.is_package = False
