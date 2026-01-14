"""Archive service for creating scan report archives.

This service handles:
- Creating zip archives of scan report files
- Listing existing archives
- Deleting report files after archiving
"""

import logging
import os
import zipfile
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class ArchiveService:
    """Service for creating and managing scan archives."""

    def __init__(self, reports_base: str = "/reports"):
        """Initialize archive service.

        Args:
            reports_base: Base directory for reports (default: /reports)
        """
        self.reports_base = Path(reports_base)
        self.archives_dir = self.reports_base / "archives"
        # Create archives directory if it doesn't exist
        self.archives_dir.mkdir(parents=True, exist_ok=True)

    def create_archive(self, scan_profile: str, file_paths: list[str]) -> tuple[str, int]:
        """Create a zip archive of the specified files.

        Args:
            scan_profile: Profile name for archive naming
            file_paths: List of absolute file paths to include

        Returns:
            Tuple of (archive_path, archive_size_bytes)
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Sanitize profile name for filename
        safe_profile = scan_profile.replace("-", "_").replace(" ", "_")
        archive_name = f"{timestamp}_{safe_profile}.zip"
        archive_path = self.archives_dir / archive_name

        files_added = 0
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in file_paths:
                if os.path.exists(file_path):
                    try:
                        # Preserve directory structure relative to reports_base
                        arcname = os.path.relpath(file_path, self.reports_base)
                        zf.write(file_path, arcname)
                        files_added += 1
                    except (OSError, ValueError) as e:
                        logger.warning(f"Could not add file to archive: {file_path} - {e}")

        if files_added == 0:
            # Remove empty archive
            archive_path.unlink(missing_ok=True)
            raise ValueError("No files could be added to archive")

        archive_size = archive_path.stat().st_size
        logger.info(f"Created archive: {archive_name} ({files_added} files, {archive_size} bytes)")
        return str(archive_path), archive_size

    def list_archives(self) -> list[dict]:
        """List all archives in the archives directory.

        Returns:
            List of archive info dicts with name, path, size_bytes, created_at
        """
        archives = []
        if not self.archives_dir.exists():
            return archives

        for f in self.archives_dir.glob("*.zip"):
            try:
                stat = f.stat()
                archives.append(
                    {
                        "name": f.name,
                        "path": str(f),
                        "size_bytes": stat.st_size,
                        "created_at": datetime.fromtimestamp(stat.st_ctime),
                    }
                )
            except OSError as e:
                logger.warning(f"Could not stat archive file: {f} - {e}")

        return sorted(archives, key=lambda x: x["created_at"], reverse=True)

    def delete_files(self, file_paths: list[str]) -> tuple[int, list[str]]:
        """Delete files from filesystem.

        Args:
            file_paths: List of absolute file paths to delete

        Returns:
            Tuple of (deleted_count, error_list)
        """
        deleted = 0
        errors = []

        for path in file_paths:
            try:
                if os.path.exists(path):
                    # Security check: ensure path is within reports directory
                    abs_path = os.path.abspath(path)
                    if not abs_path.startswith(str(self.reports_base)):
                        errors.append(f"{path}: path outside reports directory")
                        continue

                    os.remove(path)
                    deleted += 1
                    logger.debug(f"Deleted file: {path}")

                    # Try to remove empty parent directories
                    parent = os.path.dirname(path)
                    try:
                        while parent and parent != str(self.reports_base):
                            if os.path.isdir(parent) and not os.listdir(parent):
                                os.rmdir(parent)
                                parent = os.path.dirname(parent)
                            else:
                                break
                    except OSError:
                        pass  # Directory not empty, that's fine
            except OSError as e:
                errors.append(f"{path}: {str(e)}")
                logger.warning(f"Failed to delete file: {path} - {e}")

        logger.info(f"Deleted {deleted} files, {len(errors)} errors")
        return deleted, errors


# Singleton instance
_archive_service = None


def get_archive_service() -> ArchiveService:
    """Get or create the archive service instance."""
    global _archive_service
    if _archive_service is None:
        _archive_service = ArchiveService()
    return _archive_service
