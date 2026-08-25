from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    import r2pipe
except ImportError:
    r2pipe = None


logger = logging.getLogger("revllm.r2")


class R2SessionError(RuntimeError):
    pass


class R2SessionManager:
    def __init__(
        self,
        binary_path: Union[str, Path],
        radare2_path: Optional[Union[str, Path]] = None,
        analysis_cmd: str = "aaa",
    ):
        self.binary_path = Path(binary_path)
        self.radare2_path = Path(radare2_path) if radare2_path else None
        self.analysis_cmd = analysis_cmd

        self._r2: Optional[Any] = None
        self._analyzed = False

        if not self.binary_path.exists():
            raise R2SessionError(f"Binary file not found: {self.binary_path}")

        if r2pipe is None:
            raise R2SessionError(
                "r2pipe is not installed. Install it with: pip install r2pipe"
            )

    def open(self) -> None:
        if self._r2 is not None:
            return

        if self.radare2_path:
            if self.radare2_path.exists():
                r2_dir = str(self.radare2_path.resolve())
                current_path = os.environ.get("PATH", "")
                if r2_dir not in current_path.split(os.pathsep):
                    os.environ["PATH"] = r2_dir + os.pathsep + current_path
                    logger.info("Added Radare2 directory to PATH: %s", r2_dir)
            else:
                logger.warning("Radare2 path does not exist: %s", self.radare2_path)

        logger.info("Opening r2 session for binary: %s", self.binary_path)
        try:
            self._r2 = r2pipe.open(
                str(self.binary_path),
                flags=["-e", "scr.color=0"],
            )
        except Exception as exc:
            raise R2SessionError(f"Cannot open r2 session: {exc}") from exc

    def cmd(self, command: str) -> str:
        self.open()
        return self._r2.cmd(command)

    def _safe_cmd(self, command: str) -> str:
        try:
            return self._r2.cmd(command) or ""
        except Exception as exc:
            logger.warning("r2 command failed: %s (%s)", command, exc)
            return ""

    def _safe_json(self, command: str, default: Any) -> Any:
        raw = self._safe_cmd(command)
        if not raw:
            return default
        try:
            return json.loads(raw)
        except Exception:
            return default

    def analyze(self) -> None:
        self.open()
        if self._analyzed:
            return
        logger.info("Running r2 analysis command: %s", self.analysis_cmd)
        self._r2.cmd(self.analysis_cmd)
        self._analyzed = True

    def close(self) -> None:
        if self._r2 is None:
            return
        try:
            self._r2.quit()
            logger.info("r2 session closed")
        except Exception as exc:
            logger.warning("Error while closing r2 session: %s", exc)
        finally:
            self._r2 = None
            self._analyzed = False

    @staticmethod
    def _to_int(value: Any) -> Optional[int]:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError:
                return None
        return None

    def list_functions(self) -> List[Dict[str, Any]]:
        self.analyze()

        functions = self._list_functions_json()

        if functions and self._sizes_look_sane(functions):
            logger.info("Function list source: aflj")
        else:
            if functions:
                logger.warning(
                    "aflj sizes look inconsistent (max=%d), falling back to text afl",
                    max(f["size"] for f in functions),
                )
            else:
                logger.warning("aflj returned no functions, falling back to text afl")
            functions = self._list_functions_text()

        logger.info("Found %d functions", len(functions))
        return functions

    @staticmethod
    def _sizes_look_sane(functions: List[Dict[str, Any]], top_limit: int = 50_000) -> bool:
        if not functions:
            return False
        return max(f["size"] for f in functions) <= top_limit

    def _list_functions_json(self) -> List[Dict[str, Any]]:
        raw = self._safe_cmd("aflj")
        items = None
        try:
            items = json.loads(raw)
        except Exception as exc:
            logger.warning("Cannot parse aflj JSON: %s", exc)

        if not isinstance(items, list):
            return []

        functions: List[Dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            offset = self._to_int(item.get("offset", item.get("addr")))
            if offset is None or offset == 0:
                continue
            size = self._to_int(item.get("size")) or 0
            name = item.get("name", f"fcn.{offset:x}")
            functions.append(
                {
                    "address": hex(offset),
                    "offset": offset,
                    "name": name,
                    "size": size,
                }
            )

        if not functions and raw and raw.strip() not in ("", "[]"):
            logger.debug("aflj raw sample: %s", raw[:300])
        return functions

    def _list_functions_text(self) -> List[Dict[str, Any]]:
        raw = self._safe_cmd("afl")
        functions: List[Dict[str, Any]] = []
        for line in raw.strip().splitlines():
            parts = line.strip().split()
            if len(parts) < 4:
                continue
            try:
                offset = int(parts[0], 16)
                size = int(parts[2])
            except ValueError:
                continue
            if offset == 0:
                continue
            functions.append(
                {
                    "address": hex(offset),
                    "offset": offset,
                    "name": " ".join(parts[3:]),
                    "size": size,
                }
            )
        return functions

    def get_imports(self) -> List[str]:
        self.analyze()
        items = self._safe_json("iij", [])
        names = set()
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    name = item.get("name")
                    if name:
                        names.add(name)
        result = sorted(names)
        logger.info("Found %d imports", len(result))
        return result

    def get_strings(self) -> List[Dict[str, Any]]:
        self.analyze()
        items = self._safe_json("izj", [])
        strings: List[Dict[str, Any]] = []
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                s = item.get("string")
                if not s:
                    continue
                addr = self._to_int(item.get("vaddr"))
                strings.append(
                    {
                        "address": hex(addr) if addr is not None else None,
                        "string": s,
                    }
                )
        logger.info("Found %d strings", len(strings))
        return strings

    def decompile_function(self, address: str) -> Dict[str, Any]:
        """
        r2-представление функции: pdc + pdf + info + xrefs + callees.
        Декомпиляцию делает Ghidra, pdg здесь больше не используется.
        """
        self.analyze()

        addr = address if address.startswith("0x") else hex(int(address, 16))

        result: Dict[str, Any] = {
            "address": addr,
            "pdc": "",
            "pdf": "",
            "info": {},
            "xrefs_to": [],
            "callees": [],
        }

        result["pdc"] = self._safe_cmd(f"pdc @ {addr}")
        result["pdf"] = self._safe_cmd(f"pdf @ {addr}")

        info = self._safe_json(f"afij @ {addr}", [])
        if isinstance(info, list) and info and isinstance(info[0], dict):
            result["info"] = info[0]

        xrefs = self._safe_json(f"axtj @ {addr}", [])
        if isinstance(xrefs, list):
            result["xrefs_to"] = xrefs

        callees = self._safe_json(f"axfj @ {addr}", [])
        if isinstance(callees, list):
            result["callees"] = callees

        return result