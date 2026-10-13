import numpy as np
from utils.vocab import (
    PERMISSION_VOCAB,
    PERMISSION_WEIGHTS,
    API_VOCAB,
    HIGH_RISK_PERMISSIONS,
    MEDIUM_RISK_PERMISSIONS,
    LOW_RISK_PERMISSIONS,
)
from config import PERM_DIM, API_DIM, META_DIM, INPUT_DIM


class FeatureBuilder:

    def __init__(self):
        self.perm_to_idx = {perm: idx for idx, perm in enumerate(PERMISSION_VOCAB)}
        self.api_to_idx = {api: idx for idx, api in enumerate(API_VOCAB)}
        self.high_risk_set = set(HIGH_RISK_PERMISSIONS)
        self.medium_risk_set = set(MEDIUM_RISK_PERMISSIONS)
        self.low_risk_set = set(LOW_RISK_PERMISSIONS)

    def build(self, parse_result: dict) -> np.ndarray:
        """
        Build 360-dim float32 feature vector.

        Slots 0-199   : permission weighted multi-hot
        Slots 200-349 : API call binary multi-hot
        Slots 350-359 : metadata (10 normalized floats)
          [350] min_sdk / 34.0
          [351] target_sdk / 34.0
          [352] min(num_activities / 50.0, 1.0)
          [353] min(num_services / 20.0, 1.0)
          [354] min(num_receivers / 20.0, 1.0)
          [355] min(num_providers / 10.0, 1.0)
          [356] min(len(permissions) / 50.0, 1.0)
          [357] 1.0 if INTERNET permission else 0.0
          [358] 1.0 if BIND_DEVICE_ADMIN else 0.0
          [359] min(app_size_kb / 10000.0, 1.0)
        """
        vector = np.zeros(INPUT_DIM, dtype=np.float32)

        # 1. Permissions (Slots 0-199)
        declared_perms = set(parse_result.get("permissions", []))
        has_internet = False
        has_device_admin = False

        for perm in declared_perms:
            clean_perm = perm.strip()
            if clean_perm == "android.permission.INTERNET":
                has_internet = True
            if clean_perm == "android.permission.BIND_DEVICE_ADMIN":
                has_device_admin = True

            if clean_perm in self.perm_to_idx:
                idx = self.perm_to_idx[clean_perm]
                weight = PERMISSION_WEIGHTS.get(clean_perm, 0.1)
                vector[idx] = float(weight)
            else:
                # Substring matching for permission short names
                for full_p, idx in self.perm_to_idx.items():
                    if clean_perm.endswith(full_p.split(".")[-1]):
                        vector[idx] = float(PERMISSION_WEIGHTS.get(full_p, 0.1))

        # 2. API Calls (Slots 200-349)
        api_calls = parse_result.get("api_calls", [])
        api_calls_set = set(api_calls)
        ad_sdks = set(parse_result.get("ad_sdks", []))

        for idx, sig in enumerate(API_VOCAB):
            vector_idx = PERM_DIM + idx
            # Match signature, method, or readable format
            sig_name = sig.split(";")[-1].lstrip("->").strip()
            cls_name = sig.split(";")[0].split("/")[-1]
            readable_full = f"{cls_name}.{sig_name}" if sig_name else cls_name

            if (
                sig in api_calls_set
                or cls_name in api_calls_set
                or readable_full in api_calls_set
            ):
                vector[vector_idx] = 1.0
            else:
                # Check for substring match in any api_call entry
                for call in api_calls:
                    if cls_name in call or sig_name in call:
                        vector[vector_idx] = 1.0
                        break

            # If it's an ad SDK signature, also check if ad_sdks matched
            if vector[vector_idx] == 0.0 and idx in range(45, 70):
                for sdk_found in ad_sdks:
                    if sdk_found.lower() in sig.lower():
                        vector[vector_idx] = 1.0
                        break

        # 3. Metadata (Slots 350-359)
        min_sdk = float(parse_result.get("min_sdk", 21))
        target_sdk = float(parse_result.get("target_sdk", 33))
        num_act = float(parse_result.get("num_activities", 1))
        num_serv = float(parse_result.get("num_services", 0))
        num_recv = float(parse_result.get("num_receivers", 0))
        num_prov = float(parse_result.get("num_providers", 0))
        perm_count = float(len(declared_perms))
        size_kb = float(parse_result.get("app_size_kb", 2048))

        vector[350] = min(min_sdk / 34.0, 1.0)
        vector[351] = min(target_sdk / 34.0, 1.0)
        vector[352] = min(num_act / 50.0, 1.0)
        vector[353] = min(num_serv / 20.0, 1.0)
        vector[354] = min(num_recv / 20.0, 1.0)
        vector[355] = min(num_prov / 10.0, 1.0)
        vector[356] = min(perm_count / 50.0, 1.0)
        vector[357] = 1.0 if has_internet else 0.0
        vector[358] = 1.0 if has_device_admin else 0.0
        vector[359] = min(size_kb / 10000.0, 1.0)

        return vector

    def get_risk_summary(self, permissions: list) -> dict:
        """
        Returns:
        {
          "high"        : [list of HIGH risk perms found],
          "medium"      : [list of MEDIUM risk perms found],
          "low"         : [list of LOW risk perms found],
          "high_count"  : int,
          "medium_count": int,
          "low_count"   : int,
          "total"       : int
        }
        """
        high = []
        medium = []
        low = []

        for p in permissions:
            clean = p.strip()
            if clean in self.high_risk_set:
                high.append(clean)
            elif clean in self.medium_risk_set:
                medium.append(clean)
            else:
                low.append(clean)

        return {
            "high": high,
            "medium": medium,
            "low": low,
            "high_count": len(high),
            "medium_count": len(medium),
            "low_count": len(low),
            "total": len(permissions),
        }
