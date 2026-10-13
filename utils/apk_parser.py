"""
Parses Android APK files using Python built-ins only.
No external APK libraries required.
Uses zipfile + xml.etree + struct + re.
"""

import os
import re
import struct
import zipfile
from xml.etree import ElementTree as ET
from utils.vocab import (
    PERMISSION_VOCAB,
    API_VOCAB,
    API_RISK_LABELS,
    AD_SDK_NAMES,
)


class APKParser:

    def __init__(self):
        self.perm_set = set(PERMISSION_VOCAB)
        self.api_signatures = set(API_VOCAB)
        self.sdk_signatures = set(AD_SDK_NAMES.keys())

    def parse(self, apk_path: str) -> dict:
        """
        Open APK as ZIP. Extract all metadata, permissions, DEX API calls, and Ad SDKs.
        Returns:
        {
          "package_name"  : str,
          "permissions"   : list[str],
          "min_sdk"       : int,
          "target_sdk"    : int,
          "num_activities": int,
          "num_services"  : int,
          "num_receivers" : int,
          "num_providers" : int,
          "app_size_kb"   : int,
          "api_calls"     : list[str],  readable names
          "ad_sdks"       : list[str],  readable names
          "parse_success" : bool,
          "error"         : str or None
        }
        """
        if not os.path.exists(apk_path):
            return {
                "package_name": "unknown.package",
                "permissions": [],
                "min_sdk": 21,
                "target_sdk": 33,
                "num_activities": 0,
                "num_services": 0,
                "num_receivers": 0,
                "num_providers": 0,
                "app_size_kb": 0,
                "api_calls": [],
                "ad_sdks": [],
                "parse_success": False,
                "error": f"File not found: {apk_path}",
            }

        app_size_kb = max(1, int(os.path.getsize(apk_path) / 1024))

        manifest_data = {
            "package_name": "unknown.package",
            "permissions": [],
            "min_sdk": 21,
            "target_sdk": 33,
            "num_activities": 1,
            "num_services": 0,
            "num_receivers": 0,
            "num_providers": 0,
        }

        matched_apis_readable = []
        matched_sdks_readable = []
        error_msg = None

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                # 1. Parse AndroidManifest.xml
                if "AndroidManifest.xml" in zf.namelist():
                    manifest_bytes = zf.read("AndroidManifest.xml")
                    if len(manifest_bytes) >= 4 and manifest_bytes[:4] == b"\x03\x00\x08\x00":
                        parsed_manifest = self._parse_axml(manifest_bytes)
                    else:
                        parsed_manifest = self._parse_manifest_text(manifest_bytes)

                    manifest_data.update(parsed_manifest)

                # 2. Scan all classes*.dex files
                dex_files = [f for f in zf.namelist() if f.endswith(".dex")]
                all_apis = set()
                all_sdks = set()

                for dex_file in dex_files:
                    try:
                        dex_bytes = zf.read(dex_file)
                        apis, sdks = self._scan_dex(dex_bytes)
                        all_apis.update(apis)
                        all_sdks.update(sdks)
                    except Exception:
                        continue

                matched_apis_readable = sorted(list(all_apis))
                matched_sdks_readable = sorted(list(all_sdks))

        except zipfile.BadZipFile:
            error_msg = "Invalid APK format: Not a valid ZIP archive."
        except Exception as e:
            error_msg = f"APK parsing encountered an error: {str(e)}"

        return {
            "package_name": manifest_data.get("package_name") or "com.android.app",
            "permissions": sorted(list(set(manifest_data.get("permissions", [])))),
            "min_sdk": int(manifest_data.get("min_sdk", 21)),
            "target_sdk": int(manifest_data.get("target_sdk", 33)),
            "num_activities": int(manifest_data.get("num_activities", 1)),
            "num_services": int(manifest_data.get("num_services", 0)),
            "num_receivers": int(manifest_data.get("num_receivers", 0)),
            "num_providers": int(manifest_data.get("num_providers", 0)),
            "app_size_kb": app_size_kb,
            "api_calls": matched_apis_readable,
            "ad_sdks": matched_sdks_readable,
            "parse_success": error_msg is None,
            "error": error_msg,
        }

    def _parse_manifest_text(self, xml_bytes: bytes) -> dict:
        """Parse plain-text AndroidManifest.xml if uncompiled"""
        try:
            root = ET.fromstring(xml_bytes.decode("utf-8", errors="ignore"))
            package_name = root.attrib.get("package", "com.android.app")

            permissions = []
            for elem in root.findall(".//uses-permission"):
                for k, v in elem.attrib.items():
                    if "name" in k.lower():
                        permissions.append(v)

            min_sdk = 21
            target_sdk = 33
            uses_sdk = root.find(".//uses-sdk")
            if uses_sdk is not None:
                for k, v in uses_sdk.attrib.items():
                    if "minsdkversion" in k.lower().replace(":", ""):
                        try:
                            min_sdk = int(v)
                        except ValueError:
                            pass
                    if "targetsdkversion" in k.lower().replace(":", ""):
                        try:
                            target_sdk = int(v)
                        except ValueError:
                            pass

            num_activities = len(root.findall(".//activity"))
            num_services = len(root.findall(".//service"))
            num_receivers = len(root.findall(".//receiver"))
            num_providers = len(root.findall(".//provider"))

            return {
                "package_name": package_name,
                "permissions": permissions,
                "min_sdk": min_sdk,
                "target_sdk": target_sdk,
                "num_activities": max(1, num_activities),
                "num_services": num_services,
                "num_receivers": num_receivers,
                "num_providers": num_providers,
            }
        except Exception:
            return self._extract_strings_fallback(xml_bytes)

    def _parse_axml(self, data: bytes) -> dict:
        """
        Parse Android Binary XML (AXML).
        AXML header magic: 0x00080003 (bytes: \x03\x00\x08\x00 in Little Endian).
        Extract string pool chunk and scan for permissions, components, SDK levels, and package.
        """
        strings = []
        try:
            if len(data) >= 8:
                # String pool header begins around byte 8
                chunk_type, chunk_size = struct.unpack("<II", data[8:16])
                if chunk_type == 0x001C0001:  # RES_XML_RESOURCE_MAP_TYPE / STRING_POOL
                    string_count, style_count, flags, strings_start, styles_start = struct.unpack(
                        "<IIIII", data[16:36]
                    )
                    is_utf8 = bool(flags & (1 << 8))

                    # Read string offsets
                    offsets = []
                    offset_pos = 36
                    for _ in range(string_count):
                        offsets.append(struct.unpack("<I", data[offset_pos : offset_pos + 4])[0])
                        offset_pos += 4

                    pool_base = 8 + strings_start
                    for off in offsets:
                        pos = pool_base + off
                        if pos >= len(data):
                            continue
                        if is_utf8:
                            # UTF-8 string: skip length prefix
                            pos += 1
                            if pos < len(data) and (data[pos] & 0x80):
                                pos += 1
                            pos += 1
                            if pos < len(data) and (data[pos] & 0x80):
                                pos += 1
                            null_term = data.find(b"\x00", pos)
                            if null_term != -1:
                                s = data[pos:null_term].decode("utf-8", errors="ignore")
                                strings.append(s)
                        else:
                            # UTF-16 string
                            u16_len = struct.unpack("<H", data[pos : pos + 2])[0]
                            pos += 2
                            raw_s = data[pos : pos + (u16_len * 2)]
                            s = raw_s.decode("utf-16le", errors="ignore")
                            strings.append(s)
        except Exception:
            pass

        if not strings:
            return self._extract_strings_fallback(data)

        permissions = []
        package_name = "com.android.app"
        min_sdk = 21
        target_sdk = 33
        activity_count = 0
        service_count = 0
        receiver_count = 0
        provider_count = 0

        # Scan extracted strings
        for s in strings:
            if s.startswith("android.permission.") or s in self.perm_set:
                permissions.append(s)
            elif "." in s and not s.startswith("android.") and not s.startswith("http") and "/" not in s:
                if re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$", s):
                    if package_name == "com.android.app" and len(s) < 80:
                        package_name = s

        # Scan for component names or tags in strings
        for s in strings:
            s_lower = s.lower()
            if "activity" in s_lower:
                activity_count += 1
            if "service" in s_lower:
                service_count += 1
            if "receiver" in s_lower:
                receiver_count += 1
            if "provider" in s_lower:
                provider_count += 1

        # Also regex for integer SDKs
        sdk_candidates = re.findall(rb"([0-9]{1,2})\x00", data)
        for cand in sdk_candidates:
            try:
                val = int(cand)
                if 14 <= val <= 35:
                    if target_sdk == 33:
                        target_sdk = val
            except Exception:
                pass

        return {
            "package_name": package_name,
            "permissions": list(set(permissions)),
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
            "num_activities": max(1, min(activity_count, 45)),
            "num_services": min(service_count, 25),
            "num_receivers": min(receiver_count, 20),
            "num_providers": min(provider_count, 10),
        }

    def _extract_strings_fallback(self, data: bytes) -> dict:
        """Fallback regex extraction for ASCII and UTF-16 strings"""
        ascii_strings = [
            s.decode("ascii", errors="ignore")
            for s in re.findall(rb"[a-zA-Z0-9_\.\/\:\-]{4,}", data)
        ]
        permissions = [s for s in ascii_strings if s in self.perm_set or s.startswith("android.permission.")]
        pkg_candidates = [
            s
            for s in ascii_strings
            if re.match(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,}$", s)
            and not s.startswith("android.permission")
        ]
        package_name = pkg_candidates[0] if pkg_candidates else "com.example.application"

        return {
            "package_name": package_name,
            "permissions": list(set(permissions)),
            "min_sdk": 21,
            "target_sdk": 33,
            "num_activities": 1,
            "num_services": 0,
            "num_receivers": 0,
            "num_providers": 0,
        }

    def _scan_dex(self, dex_bytes: bytes) -> tuple:
        """
        Scan DEX bytes for API/SDK signatures.
        Reads string pool from DEX header or performs byte pattern matching against API_VOCAB and AD_SDK_NAMES.
        Returns: (matched_apis_readable, matched_sdks_readable)
        """
        matched_apis = set()
        matched_sdks = set()

        if len(dex_bytes) < 68:
            return ([], [])

        # Check DEX magic: dex\n035\0 or similar
        is_dex = dex_bytes.startswith(b"dex\n")

        # Extract DEX string pool offsets if standard DEX
        dex_strings = set()
        if is_dex:
            try:
                string_ids_size = struct.unpack("<I", dex_bytes[56:60])[0]
                string_ids_off = struct.unpack("<I", dex_bytes[60:64])[0]

                # Sample string offsets safely
                count = min(string_ids_size, 20000)
                for i in range(count):
                    idx_off = string_ids_off + (i * 4)
                    if idx_off + 4 > len(dex_bytes):
                        break
                    str_data_off = struct.unpack("<I", dex_bytes[idx_off : idx_off + 4])[0]
                    if str_data_off >= len(dex_bytes):
                        continue

                    # Read uleb128 string length
                    curr = str_data_off
                    while curr < len(dex_bytes) and (dex_bytes[curr] & 0x80):
                        curr += 1
                    curr += 1

                    null_pos = dex_bytes.find(b"\x00", curr)
                    if null_pos != -1 and null_pos - curr < 256:
                        s = dex_bytes[curr:null_pos].decode("utf-8", errors="ignore")
                        dex_strings.add(s)
            except Exception:
                pass

        # Match APIs and SDKs
        # 1. Check against extracted strings
        for s in dex_strings:
            for api in self.api_signatures:
                if api in s or s in api:
                    matched_apis.add(self._get_readable_name(api))
            for sdk in self.sdk_signatures:
                if sdk in s or s in sdk:
                    matched_sdks.add(self._get_readable_sdk(sdk))

        # 2. Fast raw byte scanning for any remaining signatures
        dex_text = dex_bytes[: 10 * 1024 * 1024]  # Scan up to 10MB
        for api in self.api_signatures:
            api_bytes = api.encode("utf-8")
            if api_bytes in dex_text:
                matched_apis.add(self._get_readable_name(api))

        for sdk in self.sdk_signatures:
            sdk_bytes = sdk.encode("utf-8")
            if sdk_bytes in dex_text:
                matched_sdks.add(self._get_readable_sdk(sdk))

        return (list(matched_apis), list(matched_sdks))

    def _get_readable_name(self, api_sig: str) -> str:
        """
        Lcom/example/Class;->method  →  Class.method
        Handles: class-only sigs, method sigs, nested classes
        """
        sig = api_sig.lstrip("L").replace("/", ".")
        if ";->" in sig:
            parts = sig.split(";->")
            cls_name = parts[0].split(".")[-1]
            method_name = parts[1].split("(")[0]
            return f"{cls_name}.{method_name}"
        elif ";" in sig:
            cls_name = sig.split(";")[0].split(".")[-1]
            return cls_name
        else:
            return sig.split(".")[-1]

    def _get_readable_sdk(self, sdk_sig: str) -> str:
        """Return AD_SDK_NAMES.get(sdk_sig, sdk_sig)"""
        return AD_SDK_NAMES.get(sdk_sig, sdk_sig.replace("Lcom/", "").replace("/", " ").title())
