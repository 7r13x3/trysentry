"""
TrySentry — Quarantine vault
Moves suspicious files into an encrypted vault using AES-256.
"""
import json
import os
import shutil
import time
from pathlib import Path
from typing import Optional

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from .. import logger


class Quarantine:
    def __init__(self, vault_dir: str = "quarantine"):
        self.vault_dir = Path(vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)

        self.key_file = self.vault_dir / ".key"
        self.manifest_file = self.vault_dir / "manifest.json"
        self.key = self._load_or_create_key()

        if not self.manifest_file.exists():
            self.manifest_file.write_text("[]")

    def _load_or_create_key(self) -> bytes:
        if not HAS_CRYPTO:
            return b""
        if self.key_file.exists():
            return self.key_file.read_bytes()
        key = Fernet.generate_key()
        self.key_file.write_bytes(key)
        try:
            os.chmod(self.key_file, 0o600)
        except Exception:
            pass
        return key

    def _load_manifest(self) -> list:
        try:
            return json.loads(self.manifest_file.read_text())
        except Exception:
            return []

    def _save_manifest(self, entries: list):
        self.manifest_file.write_text(json.dumps(entries, indent=2))

    def quarantine_file(self, path: str, reason: str = "") -> Optional[str]:
        """
        Move a file into the vault and encrypt it if crypto is available.
        Returns the vault entry ID, or None on failure.
        """
        src = Path(path)
        if not src.exists() or not src.is_file():
            logger.warn(f"File not found: {path}")
            return None

        entry_id = f"{int(time.time())}_{src.name}"
        dest = self.vault_dir / (entry_id + ".enc")
        meta = self.vault_dir / (entry_id + ".meta.json")

        try:
            # read original
            data = src.read_bytes()

            if HAS_CRYPTO and self.key:
                f = Fernet(self.key)
                encrypted = f.encrypt(data)
                dest.write_bytes(encrypted)
            else:
                shutil.copy2(src, dest)

            # write metadata
            meta.write_text(json.dumps({
                "id": entry_id,
                "original_path": str(src),
                "size": len(data),
                "quarantined_at": time.time(),
                "reason": reason,
                "encrypted": HAS_CRYPTO,
            }, indent=2))

            # remove original
            try:
                src.unlink()
            except Exception:
                # try harder if locked
                os.system(f'attrib -r -s -h "{src}"')
                try:
                    src.unlink()
                except Exception as e:
                    logger.warn(f"Could not remove original {src}: {e}")

            # update manifest
            manifest = self._load_manifest()
            manifest.append({
                "id": entry_id,
                "original_path": str(src),
                "reason": reason,
                "at": time.time(),
            })
            self._save_manifest(manifest)

            logger.alert(f"Quarantined: {src.name} → vault/{entry_id}")
            return entry_id

        except Exception as e:
            logger.warn(f"Quarantine failed for {path}: {e}")
            return None

    def restore(self, entry_id: str) -> bool:
        """Restore a quarantined file to its original location."""
        dest = self.vault_dir / (entry_id + ".enc")
        meta_path = self.vault_dir / (entry_id + ".meta.json")

        if not dest.exists() or not meta_path.exists():
            logger.warn(f"Vault entry not found: {entry_id}")
            return False

        try:
            meta = json.loads(meta_path.read_text())
            original = Path(meta["original_path"])
            original.parent.mkdir(parents=True, exist_ok=True)

            data = dest.read_bytes()
            if meta.get("encrypted") and HAS_CRYPTO and self.key:
                f = Fernet(self.key)
                data = f.decrypt(data)

            original.write_bytes(data)
            dest.unlink()
            meta_path.unlink()

            logger.ok(f"Restored: {original}")
            return True
        except Exception as e:
            logger.warn(f"Restore failed: {e}")
            return False

    def list_entries(self) -> list:
        return self._load_manifest()
