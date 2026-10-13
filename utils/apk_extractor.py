"""
APK Feature Extractor Module
=============================
Parses Android APK archives using standard library zip extraction and bytecode
stream analysis without external C-extensions.
Extracts:
  - Permissions from AndroidManifest.xml (Binary AXML or text XML)
  - Components (Activities, Services, Broadcast Receivers, Content Providers)
  - API signatures and dynamic evasion calls from classes*.dex
  - Ad SDK signatures
  - Package metadata and builds the 360-dimensional input vector
"""

import os
import re
import zipfile
import struct
import numpy as np
from utils.permission_vocab import (
    PERMISSION_VOCAB,
    PERMISSION_INDEX_MAP,
    PERMISSION_WEIGHTS,
    PERMISSION_RISK_MAP,
    HIGH_RISK_PERMISSIONS,
    MEDIUM_RISK_PERMISSIONS,
    LOW_RISK_PERMISSIONS
)
from utils.api_vocab import (
    API_VOCAB,
    API_INDEX_MAP,
    AD_SDK_MAP,
    SUSPICIOUS_API_HUMAN_NAMES
)


class APKFeatureExtractor:
    """
    Direct APK parser reading ZIP contents, AndroidManifest.xml string pools,
    and DEX bytecode tables.
    """

    def __init__(self):
        self.perm_vocab = PERMISSION_VOCAB
        self.api_vocab = API_VOCAB

    def extract(self, apk_path: str) -> dict:
        """
        Parses APK and builds full multimodal feature representation.
        """
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")

        app_size_bytes = os.path.getsize(apk_path)
        app_size_kb = int(app_size_bytes / 1024)

        permissions = []
        metadata = {
            "package_name": "unknown.package",
            "min_sdk": 21,
            "target_sdk": 33,
            "activities_count": 0,
            "services_count": 0,
            "receivers_count": 0,
            "providers_count": 0,
            "has_internet": False,
            "has_device_admin": False,
            "app_size_kb": app_size_kb
        }
        detected_apis = []
        detected_sdks = []

        try:
            with zipfile.ZipFile(apk_path, "r") as apk_zip:
                # 1. Parse AndroidManifest.xml
                manifest_data = self._parse_manifest(apk_zip)
                permissions = manifest_data.get("permissions", [])
                metadata.update(manifest_data.get("metadata", {}))
                metadata["app_size_kb"] = app_size_kb

                # 2. Inspect all classes.dex files
                dex_files = [f for f in apk_zip.namelist() if f.startswith("classes") and f.endswith(".dex")]
                all_dex_bytes = bytearray()
                for dex_file in dex_files:
                    try:
                        all_dex_bytes.extend(apk_zip.read(dex_file))
                    except Exception:
                        pass

                dex_bytes = bytes(all_dex_bytes)
                detected_apis = self._scan_dex_for_apis(dex_bytes)
                detected_sdks = self._scan_for_ad_sdks(dex_bytes)

        except zipfile.BadZipFile:
            # If not a valid zip, return baseline structure with heuristic inspection
            metadata["package_name"] = os.path.basename(apk_path).replace(".apk", "")

        # Categorize detected permissions and build summary
        risk_summary = self.get_risk_summary(permissions)

        # Update metadata internet & device admin flags
        if "android.permission.INTERNET" in permissions:
            metadata["has_internet"] = True
        if "android.permission.BIND_DEVICE_ADMIN" in permissions:
            metadata["has_device_admin"] = True

        # Construct 360-dimensional input vector
        feature_vector = self._build_feature_vector(permissions, detected_apis, metadata)

        # Build clean display names for suspicious APIs
        human_apis = []
        for api in detected_apis:
            if api in SUSPICIOUS_API_HUMAN_NAMES:
                human_apis.append(SUSPICIOUS_API_HUMAN_NAMES[api])
            else:
                clean = api.lstrip("L").replace(";->", ".").replace("/", ".")
                human_apis.append(clean)

        return {
            "filename": os.path.basename(apk_path),
            "package_name": metadata.get("package_name", "com.android.application"),
            "app_size_kb": app_size_kb,
            "permissions": permissions,
            "risk_summary": risk_summary,
            "detected_apis": detected_apis,
            "suspicious_apis": human_apis[:10],
            "ad_sdks": detected_sdks,
            "metadata": metadata,
            "feature_vector": feature_vector
        }

    def _parse_manifest(self, apk_zip: zipfile.ZipFile) -> dict:
        """
        Parses AndroidManifest.xml, extracting string pools and XML tags.
        Handles both compiled Android binary XML (AXML) and plain XML.
        """
        result = {
            "permissions": [],
            "metadata": {
                "package_name": "com.android.app",
                "min_sdk": 21,
                "target_sdk": 33,
                "activities_count": 2,
                "services_count": 0,
                "receivers_count": 0,
                "providers_count": 0
            }
        }

        if "AndroidManifest.xml" not in apk_zip.namelist():
            return result

        raw_manifest = apk_zip.read("AndroidManifest.xml")

        # Check if Binary AXML (Magic 0x00080003)
        if len(raw_manifest) >= 4 and raw_manifest[:4] in [b"\x03\x00\x08\x00", b"\x00\x08\x00\x03"]:
            strings = self._extract_strings_from_axml(raw_manifest)
        else:
            # Text XML
            try:
                text = raw_manifest.decode("utf-8", errors="ignore")
                strings = re.findall(r'[\w\.\-]+', text)
            except Exception:
                strings = []

        found_perms = set()
        activities = 0
        services = 0
        receivers = 0
        providers = 0
        package_candidates = []

        for s in strings:
            if "permission." in s or s in PERMISSION_INDEX_MAP:
                # Normalize permission name
                clean_p = s
                if not clean_p.startswith("android.permission.") and ("android.permission." + clean_p) in PERMISSION_INDEX_MAP:
                    clean_p = "android.permission." + clean_p
                if clean_p in PERMISSION_INDEX_MAP:
                    found_perms.add(clean_p)

            # Component counting heuristics
            low = s.lower()
            if "activity" in low and ("." in s or len(s) > 10):
                activities += 1
            elif "service" in low and ("." in s or len(s) > 10):
                services += 1
            elif "receiver" in low and ("." in s or len(s) > 10):
                receivers += 1
            elif "provider" in low and ("." in s or len(s) > 10):
                providers += 1

            # Detect package name format
            if re.match(r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,}$', s):
                package_candidates.append(s)

        result["permissions"] = list(found_perms)
        if package_candidates:
            result["metadata"]["package_name"] = package_candidates[0]

        result["metadata"]["activities_count"] = max(activities, 1)
        result["metadata"]["services_count"] = services
        result["metadata"]["receivers_count"] = receivers
        result["metadata"]["providers_count"] = providers

        return result

    def _extract_strings_from_axml(self, data: bytes) -> list:
        """
        Parses the string pool block from Android binary XML.
        """
        strings = []
        try:
            # Header check
            if len(data) < 32:
                return strings

            # Scan for String Pool chunk type (0x001C0001)
            offset = 8
            while offset + 8 < len(data):
                chunk_type, chunk_size = struct.unpack_from("<II", data, offset)
                if chunk_type == 0x001C0001:
                    # String pool found
                    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
                        "<IIIII", data, offset + 8
                    )
                    is_utf8 = (flags & (1 << 8)) != 0
                    offsets_base = offset + 28
                    strings_base = offset + strings_start

                    for i in range(min(string_count, 1000)):
                        str_offset = struct.unpack_from("<I", data, offsets_base + i * 4)[0]
                        p = strings_base + str_offset
                        if p >= len(data):
                            continue
                        if is_utf8:
                            # UTF-8 encoded
                            u8len = data[p]
                            p += 1
                            if u8len & 0x80:
                                u8len = ((u8len & 0x7F) << 8) | data[p]
                                p += 1
                            val = data[p:p + u8len].decode("utf-8", errors="ignore")
                        else:
                            # UTF-16 encoded
                            u16len = struct.unpack_from("<H", data, p)[0]
                            p += 2
                            if u16len & 0x8000:
                                u16len = ((u16len & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
                                p += 2
                            val = data[p:p + u16len * 2].decode("utf-16le", errors="ignore")
                        if val:
                            strings.append(val)
                    break
                offset += chunk_size if chunk_size > 0 else 4
        except Exception:
            # Fallback regex search on printable strings
            strings = re.findall(r'[a-zA-Z0-9_\.\$]{4,80}', data.decode("latin1", errors="ignore"))

        return strings

    def _scan_dex_for_apis(self, dex_bytes: bytes) -> list:
        """
        Scans DEX bytecode bytes for matching API signatures in API_VOCAB.
        """
        detected = []
        if not dex_bytes:
            return detected

        for api in self.api_vocab:
            # Search byte pattern
            pattern = api.encode("utf-8")
            if pattern in dex_bytes:
                detected.append(api)
            else:
                # Also try matching simplified class name
                simplified = api.lstrip("L").split(";")[0].encode("utf-8")
                if len(simplified) > 10 and simplified in dex_bytes:
                    detected.append(api)

        return detected

    def _scan_for_ad_sdks(self, dex_bytes: bytes) -> list:
        """
        Identifies prominent advertising SDK signatures in DEX bytecode.
        """
        found = []
        if not dex_bytes:
            return found

        for sig, brand in AD_SDK_MAP.items():
            if sig.encode("utf-8") in dex_bytes or sig.replace("/", ".").encode("utf-8") in dex_bytes:
                if brand not in found:
                    found.append(brand)

        return found

    def _build_feature_vector(self, permissions: list, api_calls: list, metadata: dict) -> np.ndarray:
        """
        Constructs the 360-dimensional normalized multimodal feature vector:
          Slots   0-199 : Permission multi-hot (weighted)
          Slots 200-349 : API call multi-hot
          Slots 350-359 : Metadata normalized floats
        """
        vector = np.zeros(360, dtype=np.float32)

        # 1. Permissions (0-199)
        for perm in permissions:
            if perm in PERMISSION_INDEX_MAP:
                idx = PERMISSION_INDEX_MAP[perm]
                weight = PERMISSION_WEIGHTS.get(perm, 0.1)
                vector[idx] = weight

        # 2. API Calls (200-349)
        for api in api_calls:
            if api in API_INDEX_MAP:
                idx = 200 + API_INDEX_MAP[api]
                if idx < 350:
                    vector[idx] = 1.0

        # 3. Metadata (350-359)
        min_sdk = metadata.get("min_sdk", 21)
        target_sdk = metadata.get("target_sdk", 33)
        num_activities = metadata.get("activities_count", 0)
        num_services = metadata.get("services_count", 0)
        num_receivers = metadata.get("receivers_count", 0)
        num_providers = metadata.get("providers_count", 0)
        num_permissions = len(permissions)
        has_internet = 1.0 if metadata.get("has_internet", False) else 0.0
        has_device_admin = 1.0 if metadata.get("has_device_admin", False) else 0.0
        app_size_kb = metadata.get("app_size_kb", 2048)

        vector[350] = float(min_sdk) / 34.0
        vector[351] = float(target_sdk) / 34.0
        vector[352] = min(float(num_activities) / 50.0, 1.0)
        vector[353] = min(float(num_services) / 20.0, 1.0)
        vector[354] = min(float(num_receivers) / 20.0, 1.0)
        vector[355] = min(float(num_providers) / 10.0, 1.0)
        vector[356] = min(float(num_permissions) / 50.0, 1.0)
        vector[357] = has_internet
        vector[358] = has_device_admin
        vector[359] = min(float(app_size_kb) / 10000.0, 1.0)

        return vector

    def get_risk_summary(self, permissions: list) -> dict:
        """
        Categorizes requested permissions by danger level.
        """
        high = []
        medium = []
        low = []

        for p in permissions:
            level = PERMISSION_RISK_MAP.get(p, "LOW")
            clean_name = p.replace("android.permission.", "")
            item = {
                "name": clean_name,
                "full_name": p,
                "risk": level,
                "weight": PERMISSION_WEIGHTS.get(p, 0.1)
            }
            if level == "HIGH":
                high.append(item)
            elif level == "MEDIUM":
                medium.append(item)
            else:
                low.append(item)

        return {
            "total": len(permissions),
            "high_count": len(high),
            "medium_count": len(medium),
            "low_count": len(low),
            "high_risk": high,
            "medium_risk": medium,
            "low_risk": low
        }
