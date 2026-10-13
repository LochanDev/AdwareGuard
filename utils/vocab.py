"""
AdwareGuard Feature Vocabulary — utils/vocab.py
Production-grade exhaustive vocabulary containing:
- Full 200 Android Permissions categorized by risk (High: 22, Medium: 14, Low/Normal: 164)
- Full 150 Android API Signatures categorized across 11 threat & operational vectors
- Permission risk weights (200 entries: 1.0 High, 0.5 Medium, 0.1 Low)
- Permission human-readable explainability reasons
- API category mappings for all 150 APIs
- Ad SDK signatures and human-readable network names
"""

# ==============================================================================
# 1. PERMISSIONS VOCABULARY (EXACTLY 200 PERMISSIONS)
# ==============================================================================

HIGH_RISK_PERMISSIONS = [
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_CREDENTIALS",
]

MEDIUM_RISK_PERMISSIONS = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.CAMERA",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.NFC",
    "android.permission.WAKE_LOCK",
]

LOW_RISK_PERMISSIONS = [
    "android.permission.ACCESS_CHECKIN_PROPERTIES",
    "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.ACCESS_NOTIFICATION_POLICY",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.AUTHENTICATE_ACCOUNTS",
    "android.permission.BATTERY_STATS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_APPWIDGET",
    "android.permission.BIND_AUTOFILL_SERVICE",
    "android.permission.BIND_CALL_REDIRECTION_SERVICE",
    "android.permission.BIND_CARRIER_MESSAGING_CLIENT_SERVICE",
    "android.permission.BIND_CARRIER_MESSAGING_SERVICE",
    "android.permission.BIND_CARRIER_SERVICES",
    "android.permission.BIND_CHOOSER_TARGET_SERVICE",
    "android.permission.BIND_COMPANION_DEVICE_SERVICE",
    "android.permission.BIND_CONDITION_PROVIDER_SERVICE",
    "android.permission.BIND_CONTROLS",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_DREAM_SERVICE",
    "android.permission.BIND_INCALL_SERVICE",
    "android.permission.BIND_INPUT_METHOD",
    "android.permission.BIND_MIDI_DEVICE_SERVICE",
    "android.permission.BIND_NFC_SERVICE",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_PRINT_SERVICE",
    "android.permission.BIND_QUICK_ACCESS_WALLET_SERVICE",
    "android.permission.BIND_QUICK_SETTINGS_TILE",
    "android.permission.BIND_REMOTEVIEWS",
    "android.permission.BIND_SCREENING_SERVICE",
    "android.permission.BIND_TELECOM_CONNECTION_SERVICE",
    "android.permission.BIND_TEXT_SERVICE",
    "android.permission.BIND_TV_INPUT",
    "android.permission.BIND_VISUAL_VOICEMAIL_SERVICE",
    "android.permission.BIND_VOICE_INTERACTION",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.BIND_VR_LISTENER_SERVICE",
    "android.permission.BIND_WALLPAPER",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.BLUETOOTH_PRIVILEGED",
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.BROADCAST_CLOSE_SYSTEM_DIALOGS",
    "android.permission.BROADCAST_PACKAGE_REMOVED",
    "android.permission.BROADCAST_SMS",
    "android.permission.BROADCAST_STICKY",
    "android.permission.BROADCAST_WAP_PUSH",
    "android.permission.CALL_COMPANION_APP",
    "android.permission.CALL_PRIVILEGED",
    "android.permission.CAPTURE_AUDIO_OUTPUT",
    "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
    "android.permission.CHANGE_CONFIGURATION",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_MULTICAST_STATE",
    "android.permission.CLEAR_APP_CACHE",
    "android.permission.CONTROL_LOCATION_UPDATES",
    "android.permission.DELETE_CACHE_FILES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.DIAGNOSTIC",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.DUMP",
    "android.permission.EXPAND_STATUS_BAR",
    "android.permission.FACTORY_TEST",
    "android.permission.FLASHLIGHT",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.FOREGROUND_SERVICE_CAMERA",
    "android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE",
    "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
    "android.permission.FOREGROUND_SERVICE_HEALTH",
    "android.permission.FOREGROUND_SERVICE_LOCATION",
    "android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK",
    "android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION",
    "android.permission.FOREGROUND_SERVICE_MICROPHONE",
    "android.permission.FOREGROUND_SERVICE_PHONE_CALL",
    "android.permission.FOREGROUND_SERVICE_REMOTE_MESSAGING",
    "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
    "android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED",
    "android.permission.GET_ACCOUNTS_PRIVILEGED",
    "android.permission.GET_PACKAGE_SIZE",
    "android.permission.GET_TASKS",
    "android.permission.GLOBAL_SEARCH",
    "android.permission.HIDE_NON_SYSTEM_OVERLAY_WINDOWS",
    "android.permission.HIGH_SAMPLING_RATE_SENSORS",
    "android.permission.INSTALL_LOCATION_PROVIDER",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.INSTALL_SHORTCUT",
    "android.permission.INSTANT_APP_FOREGROUND_SERVICE",
    "android.permission.INTERNAL_SYSTEM_WINDOW",
    "android.permission.KILL_BACKGROUND_PROCESSES",
    "android.permission.LOADER_USAGE_STATS",
    "android.permission.LOCATION_HARDWARE",
    "android.permission.MANAGE_ACCOUNTS",
    "android.permission.MANAGE_DEVICE_ADMINS",
    "android.permission.MANAGE_DOCUMENTS",
    "android.permission.MANAGE_MEDIA",
    "android.permission.MANAGE_ONGOING_CALLS",
    "android.permission.MANAGE_OWN_CALLS",
    "android.permission.MASTER_CLEAR",
    "android.permission.MEDIA_CONTENT_CONTROL",
    "android.permission.MODIFY_AUDIO_SETTINGS",
    "android.permission.MODIFY_PHONE_STATE",
    "android.permission.MOUNT_FORMAT_FILESYSTEMS",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.NFC_PREFERRED_PAYMENT_INFO",
    "android.permission.NFC_TRANSACTION_EVENT",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.PERSISTENT_ACTIVITY",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.READ_ASSISTANT_APP_SEARCH_DATA",
    "android.permission.READ_BASIC_PHONE_STATE",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_HOME_APP_SEARCH_DATA",
    "android.permission.READ_INPUT_STATE",
    "android.permission.READ_LOGS",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
    "android.permission.READ_NEARBY_STREAMING_POLICY",
    "android.permission.READ_PRECISE_PHONE_STATE",
    "android.permission.READ_SYNC_SETTINGS",
    "android.permission.READ_SYNC_STATS",
    "android.permission.READ_VOICEMAIL",
    "android.permission.REBOOT",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.REORDER_TASKS",
    "android.permission.REQUEST_COMPANION_PROFILE_APP_STREAMING",
    "android.permission.REQUEST_COMPANION_PROFILE_AUTOMOTIVE_PROJECTION",
    "android.permission.REQUEST_COMPANION_PROFILE_COMPUTER",
    "android.permission.REQUEST_COMPANION_PROFILE_GLASSES",
    "android.permission.REQUEST_COMPANION_PROFILE_NEARBY_DEVICE_STREAMING",
    "android.permission.REQUEST_COMPANION_PROFILE_WATCH",
    "android.permission.REQUEST_COMPANION_RUN_IN_BACKGROUND",
    "android.permission.REQUEST_COMPANION_SELF_MANAGED",
    "android.permission.REQUEST_COMPANION_START_FOREGROUND_SERVICES_FROM_BACKGROUND",
    "android.permission.REQUEST_COMPANION_USE_DATA_IN_BACKGROUND",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.REQUEST_OBSERVE_COMPANION_DEVICE_PRESENCE",
    "android.permission.REQUEST_PASSWORD_COMPLEXITY",
    "android.permission.RESTART_PACKAGES",
    "android.permission.SCHEDULE_EXACT_ALARM",
    "android.permission.SET_ALARM",
    "android.permission.SET_ALWAYS_FINISH",
    "android.permission.SET_ANIMATION_SCALE",
    "android.permission.SET_DEBUG_APP",
    "android.permission.SET_PREFERRED_APPLICATIONS",
    "android.permission.SET_PROCESS_LIMIT",
    "android.permission.SET_TIME",
    "android.permission.SET_TIME_ZONE",
    "android.permission.SET_WALLPAPER",
    "android.permission.SET_WALLPAPER_HINTS",
    "android.permission.SIGNAL_PERSISTENT_PROCESSES",
    "android.permission.START_FOREGROUND_SERVICES_FROM_BACKGROUND",
    "android.permission.START_VIEW_APP_FEATURES",
    "android.permission.START_VIEW_PERMISSION_USAGE",
    "android.permission.STATUS_BAR",
    "android.permission.SYSTEM_APPLICATION_OVERLAY",
    "android.permission.TRANSMIT_IR",
    "android.permission.UNINSTALL_SHORTCUT",
    "android.permission.UPDATE_DEVICE_STATS",
]

# Canonical 200 list & Aliases
TOP_200_PERMISSIONS = HIGH_RISK_PERMISSIONS + MEDIUM_RISK_PERMISSIONS + LOW_RISK_PERMISSIONS
PERMISSION_VOCAB = TOP_200_PERMISSIONS

assert len(TOP_200_PERMISSIONS) == 200, f"Expected 200 permissions, got {len(TOP_200_PERMISSIONS)}"
assert len(set(TOP_200_PERMISSIONS)) == 200, f"Duplicate permissions found in TOP_200_PERMISSIONS"

# Permission Weights (200 items)
PERMISSION_RISK_WEIGHTS = {}
for p in HIGH_RISK_PERMISSIONS:
    PERMISSION_RISK_WEIGHTS[p] = 1.0
for p in MEDIUM_RISK_PERMISSIONS:
    PERMISSION_RISK_WEIGHTS[p] = 0.5
for p in LOW_RISK_PERMISSIONS:
    PERMISSION_RISK_WEIGHTS[p] = 0.1

PERMISSION_WEIGHTS = PERMISSION_RISK_WEIGHTS

# Human-Readable Permission Reasons
PERMISSION_REASONS = {
    "android.permission.READ_CONTACTS": "Allows reading your complete contact list, email addresses, and phone book.",
    "android.permission.WRITE_CONTACTS": "Enables modifying or adding entries to the device contact database.",
    "android.permission.SEND_SMS": "Can send premium SMS messages silently in background without user knowledge.",
    "android.permission.RECEIVE_SMS": "Intersects incoming SMS messages, commonly abused for OTP and 2FA interception.",
    "android.permission.READ_SMS": "Accesses personal text messages and sensitive verification credentials.",
    "android.permission.RECEIVE_MMS": "Monitors incoming multimedia messages and potentially dangerous attachments.",
    "android.permission.RECEIVE_WAP_PUSH": "Receives WAP push broadcasts, historically leveraged for silent drive-by payloads.",
    "android.permission.RECORD_AUDIO": "Grants live microphone access capable of eavesdropping on ambient conversations.",
    "android.permission.ACCESS_FINE_LOCATION": "Pinpoints GPS coordinates enabling precise physical location tracking.",
    "android.permission.ACCESS_COARSE_LOCATION": "Determines approximate device location using cell tower and Wi-Fi triangulation.",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Monitors user movement continuously even when the app is closed.",
    "android.permission.READ_CALL_LOG": "Accesses complete phone call history including dialed numbers and durations.",
    "android.permission.WRITE_CALL_LOG": "Can erase incoming/outgoing call entries to conceal fraudulent dialing.",
    "android.permission.PROCESS_OUTGOING_CALLS": "Intercepts, redirects, or monitors telephone calls as they are placed.",
    "android.permission.READ_PHONE_STATE": "Harvests persistent hardware IDs (IMEI, IMSI, SIM serial) for device fingerprinting.",
    "android.permission.READ_PHONE_NUMBERS": "Directly reads the device cellular phone number.",
    "android.permission.CALL_PHONE": "Initiates outgoing phone calls without user dialer intervention.",
    "android.permission.ANSWER_PHONE_CALLS": "Permits programmatically answering incoming phone calls.",
    "android.permission.SYSTEM_ALERT_WINDOW": "Draws persistent overlay windows over other applications; primary vector for clickjacking and phishing popups.",
    "android.permission.WRITE_SETTINGS": "Modifies core system settings such as screen lock timeouts and security rules.",
    "android.permission.GET_ACCOUNTS": "Enumerates all registered Google, email, and social accounts on the phone.",
    "android.permission.USE_CREDENTIALS": "Requests authenticated tokens and credentials for registered accounts.",
    "android.permission.INTERNET": "Establishes network sockets to remote servers to download payloads or upload exfiltrated data.",
    "android.permission.ACCESS_NETWORK_STATE": "Monitors active data connectivity to schedule telemetry and ad beacons.",
    "android.permission.ACCESS_WIFI_STATE": "Reads connected Wi-Fi SSID and MAC addresses for indoor location profiling.",
    "android.permission.CHANGE_WIFI_STATE": "Connects or disconnects Wi-Fi networks programmatically.",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Can write, corrupt, or encrypt arbitrary files on shared external storage.",
    "android.permission.READ_EXTERNAL_STORAGE": "Harvests photos, documents, and downloads stored on external media.",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "Grants wide, all-files filesystem read/write privileges.",
    "android.permission.CAMERA": "Captures still photos or video feeds without visual preview.",
    "android.permission.BLUETOOTH": "Communicates with paired Bluetooth peripherals.",
    "android.permission.BLUETOOTH_ADMIN": "Discovers and pairs with nearby Bluetooth devices.",
    "android.permission.BLUETOOTH_SCAN": "Scans for surrounding Bluetooth BLE beacons for proximity tracking.",
    "android.permission.BLUETOOTH_CONNECT": "Connects to paired Bluetooth devices and audio endpoints.",
    "android.permission.NFC": "Performs Near-Field Communication transactions.",
    "android.permission.WAKE_LOCK": "Prevents processor from sleeping, keeping background adware services alive.",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Permits prompting the user to install secondary dropped APK payloads.",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Automatically launches background adware services immediately after device reboots.",
    "android.permission.INSTALL_PACKAGES": "Installs application packages directly into the operating system.",
    "android.permission.DELETE_PACKAGES": "Silently uninstalls competing applications or security tools.",
    "android.permission.BIND_DEVICE_ADMIN": "Requests device administrator privileges making the application difficult to uninstall.",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": "Mounts or unmounts filesystem partitions.",
    "android.permission.PACKAGE_USAGE_STATS": "Monitors which applications the user opens and for how long.",
    "android.permission.QUERY_ALL_PACKAGES": "Scans every installed application on the device for targeted advertising.",
    "android.permission.POST_NOTIFICATIONS": "Sends spam push notifications promoting unwanted apps and services.",
    "android.permission.DISABLE_KEYGUARD": "Disables the lock screen to display full-screen pop-up advertisements.",
    "android.permission.KILL_BACKGROUND_PROCESSES": "Terminates background tasks to prioritize adware rendering.",
}


# ==============================================================================
# 2. API VOCABULARY (EXACTLY 150 SIGNATURES)
# ==============================================================================

NETWORK_APIS = [
    "Ljava/net/HttpURLConnection",
    "Lokhttp3/OkHttpClient",
    "Ljava/net/URL;->openConnection",
    "Ljava/net/Socket",
    "Lcom/android/volley/RequestQueue",
    "Ljava/net/HttpsURLConnection",
    "Lorg/apache/http/client/HttpClient",
    "Ljava/net/DatagramSocket",
    "Ljava/net/ServerSocket",
    "Ljavax/net/ssl/SSLSocket",
    "Ljava/net/InetAddress",
    "Lorg/apache/http/impl/client/DefaultHttpClient",
    "Ljava/net/URLConnection",
    "Ljavax/net/ssl/HttpsURLConnection",
    "Ljava/net/Proxy",
]

EVASION_APIS = [
    "Ldalvik/system/DexClassLoader",
    "Ldalvik/system/PathClassLoader",
    "Ljava/lang/Runtime;->exec",
    "Ljava/lang/Class;->forName",
    "Ljava/lang/reflect/Method;->invoke",
    "Ldalvik/system/BaseDexClassLoader",
    "Ljava/lang/ProcessBuilder",
    "Ljava/lang/ClassLoader",
    "Ljava/lang/reflect/Field;->get",
    "Ljava/lang/reflect/Constructor;->newInstance",
    "Ldalvik/system/DexFile",
    "Ljava/lang/Thread;->start",
    "Ljava/security/SecureRandom",
    "Ljavax/crypto/Cipher",
    "Ljava/util/zip/ZipFile",
]

EXFILTRATION_APIS = [
    "Landroid/telephony/TelephonyManager;->getDeviceId",
    "Landroid/telephony/TelephonyManager;->getSubscriberId",
    "Landroid/telephony/TelephonyManager;->getLine1Number",
    "Landroid/location/LocationManager;->getLastKnownLocation",
    "Landroid/content/ContentResolver;->query",
    "Landroid/telephony/SmsManager;->sendTextMessage",
    "Landroid/accounts/AccountManager;->getAccounts",
    "Landroid/net/wifi/WifiManager;->getScanResults",
    "Landroid/hardware/Camera;->takePicture",
    "Landroid/media/AudioRecord;->startRecording",
    "Landroid/provider/Contacts$People",
    "Landroid/provider/CallLog$Calls",
    "Landroid/provider/Telephony$Sms",
    "Landroid/provider/Settings$Secure;->getString",
    "Landroid/os/Build;->SERIAL",
]

AD_SDK_SIGNATURES_LIST = [
    "Lcom/google/android/gms/ads",
    "Lcom/facebook/ads",
    "Lcom/unity3d/ads",
    "Lcom/applovin",
    "Lcom/chartboost",
    "Lcom/startapp",
    "Lcom/airpush",
    "Lcom/leadbolt",
    "Lcom/sendDroid",
    "Lcom/tapjoy",
    "Lcom/inmobi",
    "Lcom/flurry",
    "Lcom/mopub",
    "Lcom/millennialmedia",
    "Lcom/mobvista",
    "Lcom/vungle",
    "Lcom/ironsource",
    "Lcom/adcolony",
    "Lcom/appnext",
    "Lcom/supersonic",
    "Lcom/admarvel",
    "Lcom/adwhirl",
    "Lcom/mdotm",
    "Lcom/nostra13",
    "Lcom/squareup/picasso",
]

SYSTEM_ABUSE_APIS = [
    "Landroid/app/admin/DevicePolicyManager",
    "Landroid/content/pm/PackageManager;->getInstalledPackages",
    "Landroid/os/PowerManager;->newWakeLock",
    "Landroid/app/NotificationManager",
    "Landroid/content/Intent;->setAction",
    "Landroid/app/AlarmManager;->setRepeating",
    "Landroid/content/BroadcastReceiver",
    "Landroid/os/Handler;->postDelayed",
    "Landroid/content/SharedPreferences",
    "Landroid/app/ActivityManager;->getRunningServices",
    "Landroid/net/ConnectivityManager;->getActiveNetworkInfo",
    "Landroid/os/IBinder",
    "Landroid/app/Service;->onStartCommand",
    "Landroid/content/pm/PackageManager;->checkPermission",
    "Landroid/os/Environment;->getExternalStorageDirectory",
    "Landroid/telephony/TelephonyManager;->getNetworkType",
    "Landroid/content/Context;->getSystemService",
    "Landroid/view/WindowManager;->addView",
    "Landroid/app/KeyguardManager",
    "Landroid/hardware/fingerprint/FingerprintManager",
]

CRYPTO_APIS = [
    "Ljava/security/MessageDigest;->getInstance",
    "Ljavax/crypto/spec/SecretKeySpec",
    "Ljava/security/KeyStore",
    "Ljavax/crypto/Mac",
    "Ljava/security/cert/CertificateFactory",
    "Ljavax/net/ssl/TrustManager",
    "Ljavax/net/ssl/X509TrustManager",
    "Ljava/security/KeyPairGenerator",
    "Ljavax/crypto/CipherInputStream",
    "Ljavax/crypto/CipherOutputStream",
]

HARDWARE_APIS = [
    "Landroid/hardware/SensorManager;->getDefaultSensor",
    "Landroid/hardware/SensorManager;->registerListener",
    "Landroid/bluetooth/BluetoothAdapter;->getDefaultAdapter",
    "Landroid/nfc/NfcAdapter;->getDefaultAdapter",
    "Landroid/hardware/camera2/CameraManager",
    "Landroid/media/MediaPlayer;->start",
    "Landroid/media/MediaRecorder;->start",
    "Landroid/os/Vibrator;->vibrate",
    "Landroid/hardware/usb/UsbManager",
    "Landroid/hardware/biometrics/BiometricPrompt",
]

STORAGE_APIS = [
    "Ljava/io/FileInputStream",
    "Ljava/io/FileOutputStream",
    "Ljava/io/File;->delete",
    "Ljava/io/File;->createNewFile",
    "Ljava/io/BufferedReader;->readLine",
    "Ljava/io/InputStreamReader",
    "Ljava/io/ByteArrayOutputStream",
    "Ljava/io/DataOutputStream",
    "Ljava/io/RandomAccessFile",
    "Landroid/database/sqlite/SQLiteDatabase",
]

IPC_APIS = [
    "Landroid/content/Context;->sendBroadcast",
    "Landroid/content/Context;->startService",
    "Landroid/content/Context;->startActivity",
    "Landroid/content/IntentFilter;->addAction",
    "Landroid/os/Process;->killProcess",
    "Landroid/os/SystemClock;->sleep",
    "Landroid/os/SystemProperties;->get",
    "Landroid/content/pm/PackageManager;->getPackageInfo",
    "Landroid/app/PendingIntent;->getActivity",
    "Landroid/app/PendingIntent;->getBroadcast",
]

WEB_APIS = [
    "Landroid/webkit/WebView;->loadUrl",
    "Landroid/webkit/WebSettings;->setJavaScriptEnabled",
    "Landroid/webkit/WebViewClient",
    "Landroid/webkit/WebChromeClient",
    "Landroid/widget/Toast;->makeText",
    "Landroid/app/AlertDialog$Builder;->show",
    "Landroid/widget/RemoteViews",
    "Landroid/view/LayoutInflater;->inflate",
    "Landroid/graphics/BitmapFactory;->decodeFile",
    "Landroid/graphics/Bitmap;->compress",
]

TELEPHONY_APIS = [
    "Landroid/telephony/SmsMessage;->createFromPdu",
    "Landroid/telephony/TelephonyManager;->getSimCountryIso",
    "Landroid/telephony/TelephonyManager;->getSimOperatorName",
    "Landroid/telephony/TelephonyManager;->getSimSerialNumber",
    "Landroid/telephony/TelephonyManager;->getNetworkOperatorName",
    "Landroid/telephony/TelephonyManager;->getCallState",
    "Landroid/telephony/gsm/SmsManager",
    "Landroid/telephony/SubscriptionManager;->getActiveSubscriptionInfoList",
    "Landroid/telephony/CellInfoGsm;->getCellIdentity",
    "Landroid/net/Uri;->parse",
]

# Canonical 150 list & Aliases
TOP_150_APIS = (
    NETWORK_APIS
    + EVASION_APIS
    + EXFILTRATION_APIS
    + AD_SDK_SIGNATURES_LIST
    + SYSTEM_ABUSE_APIS
    + CRYPTO_APIS
    + HARDWARE_APIS
    + STORAGE_APIS
    + IPC_APIS
    + WEB_APIS
    + TELEPHONY_APIS
)

API_VOCAB = TOP_150_APIS

assert len(TOP_150_APIS) == 150, f"Expected 150 APIs, got {len(TOP_150_APIS)}"
assert len(set(TOP_150_APIS)) == 150, f"Duplicate APIs found in TOP_150_APIS"

# API Categories (150 items)
API_CATEGORIES = {}
for api in NETWORK_APIS:
    API_CATEGORIES[api] = "Network Communication"
for api in EVASION_APIS:
    API_CATEGORIES[api] = "Evasion / Dynamic Reflection"
for api in EXFILTRATION_APIS:
    API_CATEGORIES[api] = "Data Exfiltration"
for api in AD_SDK_SIGNATURES_LIST:
    API_CATEGORIES[api] = "Ad SDK Integration"
for api in SYSTEM_ABUSE_APIS:
    API_CATEGORIES[api] = "System Abuse & Overlays"
for api in CRYPTO_APIS:
    API_CATEGORIES[api] = "Cryptographic Operations"
for api in HARDWARE_APIS:
    API_CATEGORIES[api] = "Hardware & Sensor Access"
for api in STORAGE_APIS:
    API_CATEGORIES[api] = "Storage & Local I/O"
for api in IPC_APIS:
    API_CATEGORIES[api] = "IPC & OS Subsystem"
for api in WEB_APIS:
    API_CATEGORIES[api] = "Web & UI Manipulation"
for api in TELEPHONY_APIS:
    API_CATEGORIES[api] = "Telephony & SMS Messaging"

# Alias for backwards compatibility
API_RISK_LABELS = API_CATEGORIES

# Ad SDK Clean Names Dictionary (25 items)
AD_SDK_SIGNATURES = {
    "Lcom/google/android/gms/ads": "Google AdMob",
    "Lcom/facebook/ads": "Facebook Audience Network",
    "Lcom/unity3d/ads": "Unity Ads",
    "Lcom/applovin": "AppLovin",
    "Lcom/chartboost": "Chartboost",
    "Lcom/startapp": "StartApp",
    "Lcom/airpush": "Airpush",
    "Lcom/leadbolt": "Leadbolt",
    "Lcom/sendDroid": "SendDroid",
    "Lcom/tapjoy": "Tapjoy",
    "Lcom/inmobi": "InMobi",
    "Lcom/flurry": "Flurry",
    "Lcom/mopub": "MoPub",
    "Lcom/millennialmedia": "Millennial Media",
    "Lcom/mobvista": "Mobvista",
    "Lcom/vungle": "Vungle",
    "Lcom/ironsource": "IronSource",
    "Lcom/adcolony": "AdColony",
    "Lcom/appnext": "Appnext",
    "Lcom/supersonic": "Supersonic",
    "Lcom/admarvel": "AdMarvel",
    "Lcom/adwhirl": "AdWhirl",
    "Lcom/mdotm": "MdotM",
    "Lcom/nostra13": "Nostra13",
    "Lcom/squareup/picasso": "Picasso Ad Loader",
}

AD_SDK_NAMES = AD_SDK_SIGNATURES
