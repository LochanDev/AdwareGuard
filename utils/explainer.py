"""
Explainer module for AdwareGuard.
Transforms raw model outputs, permission analysis, and API signatures
into plain-English security intelligence and risk assessments.
"""

from utils.vocab import (
    PERMISSION_WEIGHTS,
    API_RISK_LABELS,
    HIGH_RISK_PERMISSIONS,
    MEDIUM_RISK_PERMISSIONS,
)
from config import RISK_LEVELS


class Explainer:

    def __init__(self):
        self.high_risk_set = set(HIGH_RISK_PERMISSIONS)
        self.medium_risk_set = set(MEDIUM_RISK_PERMISSIONS)

        # Dictionary of human-readable permission reasons
        self.permission_reasons = {
            "android.permission.READ_CONTACTS": "Allows reading your complete contact list and address book.",
            "android.permission.SEND_SMS": "Can send SMS messages in the background without user confirmation.",
            "android.permission.RECEIVE_SMS": "Can intercept incoming SMS messages, including two-factor verification codes.",
            "android.permission.READ_SMS": "Allows reading stored SMS messages containing private conversations and OTPs.",
            "android.permission.RECORD_AUDIO": "Can access your device microphone to record conversations without notice.",
            "android.permission.ACCESS_FINE_LOCATION": "Tracks your precise GPS coordinates in real-time.",
            "android.permission.ACCESS_COARSE_LOCATION": "Determines your approximate geographic location using cell towers and Wi-Fi.",
            "android.permission.READ_CALL_LOG": "Allows reading private phone call logs, durations, and caller details.",
            "android.permission.WRITE_CALL_LOG": "Can modify device call logs to hide unauthorized incoming or outgoing calls.",
            "android.permission.PROCESS_OUTGOING_CALLS": "Can monitor, redirect, or abort outgoing phone calls.",
            "android.permission.READ_PHONE_STATE": "Accesses telephony state, phone number, network operator, and cellular IDs.",
            "android.permission.CALL_PHONE": "Can dial phone numbers and initiate calls without opening the dialer UI.",
            "android.permission.SYSTEM_ALERT_WINDOW": "Displays floating overlay windows over other applications, often used for clickjacking or phishing.",
            "android.permission.WRITE_SETTINGS": "Modifies system configuration and security settings without confirmation.",
            "android.permission.GET_ACCOUNTS": "Reads the list of Google and email accounts configured on your device.",
            "android.permission.USE_CREDENTIALS": "Can request authentication tokens for user accounts.",
            "android.permission.MANAGE_ACCOUNTS": "Can add, remove, and manage account credentials on the device.",
            "android.permission.BIND_DEVICE_ADMIN": "Requests device administrator privilege to enforce lockouts, wipe device, or prevent uninstallation.",
            "android.permission.RECEIVE_BOOT_COMPLETED": "Automatically launches malicious background services as soon as the phone boots.",
            "android.permission.INSTALL_PACKAGES": "Installs additional APK packages without navigating through the official app store.",
            "android.permission.DELETE_PACKAGES": "Deletes or uninstalls applications from the device without user approval.",
            "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": "Mounts and unmounts device file systems for external storage.",
            "android.permission.INTERNET": "Opens network sockets to communicate with remote command-and-control servers or ad networks.",
            "android.permission.ACCESS_NETWORK_STATE": "Monitors network connection availability, bandwidth, and connection type.",
            "android.permission.ACCESS_WIFI_STATE": "Reads detailed information about Wi-Fi networks, SSID, and signal strength.",
            "android.permission.CHANGE_WIFI_STATE": "Can turn Wi-Fi on or off and connect to unverified Wi-Fi networks.",
            "android.permission.WRITE_EXTERNAL_STORAGE": "Can write, modify, or delete files stored in shared device storage.",
            "android.permission.READ_EXTERNAL_STORAGE": "Allows scanning and reading personal photos, documents, and downloads on storage.",
            "android.permission.CAMERA": "Accesses device cameras to capture photos and video streams.",
            "android.permission.BLUETOOTH": "Connects to paired Bluetooth peripherals and broadcasting devices.",
            "android.permission.BLUETOOTH_ADMIN": "Discovers and pairs with nearby Bluetooth devices without user prompt.",
            "android.permission.NFC": "Performs Near Field Communication transactions and data exchange.",
            "android.permission.VIBRATE": "Controls the device vibration motor for alerts and haptic feedback.",
            "android.permission.WAKE_LOCK": "Prevents the device processor from sleeping to run persistent tasks.",
            "android.permission.FOREGROUND_SERVICE": "Runs persistent visible tasks in the notification tray to resist termination.",
            "android.permission.REQUEST_INSTALL_PACKAGES": "Prompts the operating system to install external APK binaries.",
            "android.permission.QUERY_ALL_PACKAGES": "Inventories every application installed on the operating system for profiling.",
            "android.permission.DISABLE_KEYGUARD": "Disables lock screen security so background routines run unchecked.",
            "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": "Bypasses operating system battery saver restrictions to stay active.",
            "android.permission.POST_NOTIFICATIONS": "Sends promotional or deceptive push notifications directly to the lock screen.",
            "android.permission.KILL_BACKGROUND_PROCESSES": "Forces background processes to terminate to monopolize system resources.",
            "android.permission.ACCESS_BACKGROUND_LOCATION": "Continues monitoring physical movement even when the application is closed.",
        }

        # Human-readable API reasons
        self.api_reasons = {
            "TelephonyManager.getDeviceId": "Reads your unique device hardware identifier (IMEI) for tracking.",
            "TelephonyManager.getSubscriberId": "Extracts your cellular subscriber identity (IMSI) without notice.",
            "TelephonyManager.getLine1Number": "Reads the device telephone number directly from SIM card memory.",
            "LocationManager.getLastKnownLocation": "Queries the most recent precise GPS coordinates of the device.",
            "ContentResolver.query": "Queries private device databases containing SMS, contacts, and calendar records.",
            "SmsManager.sendTextMessage": "Sends premium-rate SMS messages behind the scenes.",
            "AccountManager.getAccounts": "Retrieves registered email accounts and user identifiers.",
            "WifiManager.getScanResults": "Gathers nearby Wi-Fi BSSID access points to triangulate physical location.",
            "Camera.takePicture": "Activates the camera to capture photographs without showing a preview.",
            "AudioRecord.startRecording": "Activates audio input streaming from the microphone.",
            "DexClassLoader": "Loads uninspected executable code dynamically at runtime to evade detection.",
            "PathClassLoader": "Executes external classes and auxiliary code payloads.",
            "Runtime.exec": "Executes low-level command-line shell commands directly on the operating system.",
            "Class.forName": "Uses reflection to dynamically invoke concealed internal APIs and bypass sandbox rules.",
            "Method.invoke": "Executes sensitive system methods dynamically to thwart static code reviews.",
            "ProcessBuilder": "Spawns unauthorized sub-processes and shell instances.",
            "DevicePolicyManager": "Interacts with device administration policies to lock or control hardware features.",
            "PackageManager.getInstalledPackages": "Enumerates all apps installed on your device to build a behavioral profile.",
            "PowerManager.newWakeLock": "Forces the CPU to remain active to run background ads and miners.",
            "NotificationManager": "Injects notifications and pop-up alerts into the user interface.",
            "AlarmManager.setRepeating": "Schedules persistent wake-ups to periodically display advertisements.",
            "WindowManager.addView": "Draws invisible overlays or unclosable pop-up banners on top of other apps.",
            "HttpURLConnection": "Establishes HTTP network traffic to transmit telemetry or fetch ad banners.",
            "OkHttpClient": "High-performance HTTP client used for transmitting data or downloading assets.",
            "Socket": "Opens direct TCP socket communication with external network endpoints.",
        }

    def explain(
        self,
        verdict: str,
        confidence: float,
        permissions: list,
        api_calls: list,
        ad_sdks: list,
        probabilities: dict,
    ) -> dict:
        """
        Produce a comprehensive, plain-English security report.
        """
        risk_level = RISK_LEVELS.get(verdict, "LOW")

        # Process permissions with reason and risk classification
        risk_permissions = []
        for p in permissions:
            weight = PERMISSION_WEIGHTS.get(p, 0.1)
            short_name = p.split(".")[-1]
            if p in self.high_risk_set:
                p_risk = "HIGH"
            elif p in self.medium_risk_set:
                p_risk = "MEDIUM"
            else:
                p_risk = "LOW"

            reason = self._get_permission_reason(p)
            risk_permissions.append(
                {
                    "name": short_name,
                    "full": p,
                    "weight": weight,
                    "risk": p_risk,
                    "reason": reason,
                }
            )

        # Sort permissions by risk priority (HIGH -> MEDIUM -> LOW)
        risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        risk_permissions.sort(key=lambda x: (risk_order.get(x["risk"], 3), -x["weight"]))

        # Process suspicious APIs
        suspicious_apis = []
        for api in api_calls:
            category = "Suspicious Behavior"
            for sig, cat in API_RISK_LABELS.items():
                sig_short = sig.split(";")[-1].lstrip("->").strip()
                cls_short = sig.split(";")[0].split("/")[-1]
                if api == f"{cls_short}.{sig_short}" or api == cls_short or api in sig:
                    category = cat
                    break

            reason = self._get_api_reason(api)
            suspicious_apis.append(
                {
                    "name": api,
                    "category": category,
                    "reason": reason,
                }
            )

        # Process Ad SDKs
        ad_sdk_entries = []
        for sdk in ad_sdks:
            ad_sdk_entries.append(
                {
                    "name": sdk,
                    "reason": f"Monetization and advertising library. Frequently displays full-screen interstitials, tracks advertising IDs, and consumes background data.",
                }
            )

        plain_english = self._get_plain_english(verdict, permissions, api_calls, ad_sdks)
        what_to_do = self._get_what_to_do(verdict, confidence)

        return {
            "verdict": verdict,
            "confidence": round(confidence, 1),
            "risk_level": risk_level,
            "plain_english": plain_english,
            "risk_permissions": risk_permissions,
            "suspicious_apis": suspicious_apis,
            "ad_sdks": ad_sdk_entries,
            "what_to_do": what_to_do,
            "probabilities": {k: round(v, 1) for k, v in probabilities.items()},
        }

    def _get_plain_english(
        self, verdict: str, permissions: list, api_calls: list, ad_sdks: list
    ) -> str:
        """
        Generate 2-3 clean, plain-English sentences without technical jargon or dataset names.
        """
        has_ads = len(ad_sdks) > 0
        ad_names = ", ".join(ad_sdks[:2]) if has_ads else ""

        high_risk_found = [p.split(".")[-1] for p in permissions if p in self.high_risk_set]
        high_str = ", ".join(high_risk_found[:2]) if high_risk_found else ""

        if verdict == "SAFE":
            if permissions:
                return (
                    f"This application exhibits standard, benign mobile behavior with well-scoped access. "
                    f"No covert ad distribution or malicious payloads were identified during deep structural inspection. "
                    f"The declared components align with legitimate application functionality."
                )
            return (
                "This application exhibits minimal system access and standard software design. "
                "Our analysis verified that no intrusive ad trackers, background telemetry, or hostile components are bundled. "
                "The application is clean and safe for routine mobile installation."
            )

        elif verdict == "ADWARE":
            if has_ads and high_str:
                return (
                    f"This package contains aggressive monetization frameworks including {ad_names} paired with sensitive permissions like {high_str}. "
                    f"The application is configured to harvest device telemetry, display persistent intrusive advertisements, and run unsolicited background advertising routines. "
                    f"These patterns represent an unwanted privacy and battery drain hazard."
                )
            elif has_ads:
                return (
                    f"This application bundles commercial ad SDKs ({ad_names}) programmed for high-frequency promotional display. "
                    f"It initiates background connections to external advertising networks and collects user identifiers for commercial tracking. "
                    f"Users are likely to experience disruptive pop-ups and unexpected data usage."
                )
            else:
                return (
                    "This application exhibits prominent adware behaviors, including recurring background wake-locks and unrequested network ad calls. "
                    "It seeks unauthorized access to system identifiers to facilitate commercial user profiling without explicit utility. "
                    "The behavior strongly indicates aggressive adware."
                )

        else:  # MALWARE
            if high_str:
                return (
                    f"This application exhibits critical threat vectors with high-risk permissions such as {high_str} and evasion routines. "
                    f"The code structure shows characteristics of malicious Trojan behavior, device exfiltration, and stealth execution. "
                    f"Installation poses an immediate danger to device security and personal privacy."
                )
            return (
                "This application incorporates hostile behavioral signatures, including dynamic code execution and privileged access attempts. "
                "It demonstrates patterns consistent with credential harvesting, device abuse, and stealthy persistence. "
                "The software poses a severe risk to your mobile device."
            )

    def _get_permission_reason(self, permission: str) -> str:
        """
        Human-readable reason for any Android permission.
        """
        if permission in self.permission_reasons:
            return self.permission_reasons[permission]

        short_name = permission.split(".")[-1].replace("_", " ").title()
        if "Location" in short_name:
            return f"Requests access to device physical positioning ({short_name})."
        elif "Bluetooth" in short_name:
            return f"Requests access to local Bluetooth radio communications ({short_name})."
        elif "Wifi" in short_name or "Network" in short_name:
            return f"Accesses local wireless or cellular connectivity state ({short_name})."
        elif "Storage" in short_name or "Media" in short_name:
            return f"Accesses media files or internal storage structures ({short_name})."
        elif "Audio" in short_name or "Camera" in short_name:
            return f"Interacts with audio or video recording hardware ({short_name})."
        elif "Bind" in short_name:
            return f"Binds to core system subsystem service ({short_name})."
        else:
            return f"Grants application privilege to execute {short_name} operations."

    def _get_api_reason(self, api_name: str) -> str:
        """
        Human-readable reason for an API call.
        """
        if api_name in self.api_reasons:
            return self.api_reasons[api_name]

        for sig, reason in self.api_reasons.items():
            if sig in api_name or api_name in sig:
                return reason

        name_lower = api_name.lower()
        if "device" in name_lower or "imei" in name_lower or "serial" in name_lower:
            return "Attempts to read unique hardware serial or device identifiers."
        elif "location" in name_lower or "gps" in name_lower:
            return "Queries geographical coordinates and physical user location."
        elif "classloader" in name_lower or "exec" in name_lower or "reflect" in name_lower:
            return "Executes dynamic reflection or external binary code payloads."
        elif "sms" in name_lower or "telephony" in name_lower:
            return "Accesses cellular messaging or telephony metadata."
        elif "window" in name_lower or "alert" in name_lower:
            return "Creates intrusive floating window views on screen."
        elif "admin" in name_lower or "policy" in name_lower:
            return "Interacts with administrative system privilege controls."
        elif "http" in name_lower or "socket" in name_lower or "url" in name_lower:
            return "Initiates external network communication with remote servers."
        else:
            return "Performs low-level system or component interaction."

    def _get_what_to_do(self, verdict: str, confidence: float) -> str:
        """
        Actionable advice based on verdict and confidence level.
        """
        if verdict == "SAFE":
            if confidence >= 85.0:
                return (
                    "This app appears safe to use. Our multi-vector inspection detected no abusive adware "
                    "payloads or malicious permissions. You can install and use it with standard mobile security confidence."
                )
            else:
                return (
                    "Likely safe, but exercise normal caution. The application exhibits low overall risk, "
                    "though you should verify permission requests during initial setup."
                )
        elif verdict == "ADWARE":
            return (
                "We recommend avoiding this application. It is engineered to aggressively display unwanted advertisements, "
                "track your online activity, and consume background battery and mobile bandwidth. "
                "If already installed, consider uninstalling it."
            )
        else:  # MALWARE
            return (
                "Do not install this application under any circumstance. If already present on your mobile phone, "
                "remove it immediately and run a comprehensive device security scan to ensure no persistent services remain."
            )
