"""Wi-Fi scanning on Windows using the native `netsh` CLI and WlanScan API.

We deliberately avoid third-party Wi-Fi libraries (e.g. pywifi) because they
are poorly maintained and unreliable across driver versions. Shelling out to
the OS-native tool is slower per call but far more dependable.
"""

import ctypes
from ctypes import wintypes
import re
import subprocess
import sys
import time

# netsh is a console app, so every subprocess.run() call against it briefly
# flashes a console window of its own on Windows -- even though this app
# itself runs with no console (see packaging/wifiguard.spec, console=False).
# Each Wi-Fi scan shells out to netsh, so without this the user sees a
# command-prompt window flash on every refresh. CREATE_NO_WINDOW tells
# Windows not to allocate a console for the child process at all.
# subprocess.CREATE_NO_WINDOW only exists on Windows, so guard it for the
# Linux/macOS case where this module still gets imported (even if unused).
_NO_WINDOW_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

# Settle time (in seconds) for Windows' active hardware sweep to finish.
# Kept tight (1.5s) to support near real-time scan cycles.
_SCAN_SETTLE_SECONDS = 1.5

# Maximum age (in seconds) of a beacon timestamp before an AP is considered offline.
# Windows WLAN AutoConfig caches BSS entries for several minutes after an AP
# is turned off or leaves range, causing `netsh` to keep showing it until
# the user toggles Wi-Fi. Active APs always beacon every 100ms, so after a
# completed scan they always have age < 300ms. Any AP turned off BEFORE the
# current scan starts has age > (_SCAN_SETTLE_SECONDS ≈ 1.5s).
# We use 3.0s to give a comfortable margin above the 1.5s settle floor while
# still dropping stale entries within one extra scan cycle (≤3s after the AP
# goes offline). Lowering this further risks false-positives on slow drivers.
_MAX_BSSID_AGE_SECONDS = 3.0

# Native Wifi API definitions (wlanapi.dll)
WLAN_API_VERSION_2_0 = 2
ERROR_SUCCESS = 0
ERROR_NDIS_DOT11_MEDIA_IN_USE = 0x80342002


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [
        ("InterfaceGuid", GUID),
        ("strInterfaceDescription", wintypes.WCHAR * 256),
        ("isState", wintypes.DWORD),
    ]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfItems", wintypes.DWORD),
        ("dwIndex", wintypes.DWORD),
        ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),
    ]


class DOT11_SSID(ctypes.Structure):
    _fields_ = [
        ("uSSIDLength", wintypes.ULONG),
        ("ucSSID", ctypes.c_char * 32),
    ]


DOT11_MAC_ADDRESS = ctypes.c_ubyte * 6


class WLAN_RATE_SET(ctypes.Structure):
    _fields_ = [
        ("uRateSetLength", wintypes.ULONG),
        ("usRateSet", wintypes.USHORT * 126),
    ]


class WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),
        ("uPhyId", wintypes.ULONG),
        ("dot11Bssid", DOT11_MAC_ADDRESS),
        ("dot11BssType", wintypes.ULONG),
        ("dot11BssPhyType", wintypes.ULONG),
        ("lRssi", ctypes.c_long),
        ("uLinkQuality", wintypes.ULONG),
        ("bInRegDomain", wintypes.BOOLEAN),
        ("usBeaconPeriod", wintypes.USHORT),
        ("ullTimestamp", ctypes.c_ulonglong),
        ("ullHostTimestamp", ctypes.c_ulonglong),
        ("usCapabilityInformation", wintypes.USHORT),
        ("ulChCenterFrequency", wintypes.ULONG),
        ("wlanRateSet", WLAN_RATE_SET),
        ("ulIeOffset", wintypes.ULONG),
        ("ulIeSize", wintypes.ULONG),
    ]


class WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [
        ("dwTotalSize", wintypes.DWORD),
        ("dwNumberOfItems", wintypes.DWORD),
        ("wlanBssEntries", WLAN_BSS_ENTRY * 1),
    ]


def _init_wlan_api():
    """Load wlanapi.dll and configure strict 64-bit C ABI prototypes."""
    if sys.platform != "win32":
        return None, None

    try:
        wlanapi = ctypes.windll.wlanapi
        kernel32 = ctypes.windll.kernel32

        wlanapi.WlanOpenHandle.argtypes = [
            wintypes.DWORD,
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.HANDLE),
        ]
        wlanapi.WlanOpenHandle.restype = wintypes.DWORD

        wlanapi.WlanCloseHandle.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
        ]
        wlanapi.WlanCloseHandle.restype = wintypes.DWORD

        wlanapi.WlanEnumInterfaces.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            ctypes.POINTER(ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)),
        ]
        wlanapi.WlanEnumInterfaces.restype = wintypes.DWORD

        wlanapi.WlanScan.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(GUID),
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.LPVOID,
        ]
        wlanapi.WlanScan.restype = wintypes.DWORD

        wlanapi.WlanGetNetworkBssList.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(GUID),
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.LPVOID,
            ctypes.POINTER(ctypes.POINTER(WLAN_BSS_LIST)),
        ]
        wlanapi.WlanGetNetworkBssList.restype = wintypes.DWORD

        wlanapi.WlanFreeMemory.argtypes = [wintypes.LPVOID]
        wlanapi.WlanFreeMemory.restype = None

        kernel32.GetSystemTimeAsFileTime.argtypes = [ctypes.POINTER(wintypes.FILETIME)]
        kernel32.GetSystemTimeAsFileTime.restype = None

        return wlanapi, kernel32
    except Exception:
        return None, None


def _trigger_scan() -> bool:
    """Ask Windows' WLAN AutoConfig service to scan right now.

    `netsh wlan show networks` never triggers a hardware scan itself -- it
    only reads whatever Windows' WLAN AutoConfig service already has cached.
    The service refreshes that cache on its own schedule (roughly every 60s
    when idle, far less often while already connected to a network). That's
    why a new or changed access point could take a long time to appear, and
    why opening Windows' own Wi-Fi settings/flyout made it show up
    immediately: that UI calls the Native Wifi API `WlanScan` function
    directly.

    `netsh` does not have a `scan` subcommand, so we invoke `WlanScan`
    directly via `wlanapi.dll` using standard library `ctypes`. This issues
    the exact same hardware scan request as Windows Settings, without
    requiring 3rd-party dependencies or popping up console windows.

    Returns True if a scan was successfully initiated (or already in progress).
    """
    wlanapi, _ = _init_wlan_api()
    if not wlanapi:
        return False

    client_handle = wintypes.HANDLE()
    negotiated_version = wintypes.DWORD()

    try:
        ret = wlanapi.WlanOpenHandle(
            WLAN_API_VERSION_2_0,
            None,
            ctypes.byref(negotiated_version),
            ctypes.byref(client_handle),
        )
        if ret != ERROR_SUCCESS:
            return False
    except Exception:
        return False

    try:
        pp_list = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        ret = wlanapi.WlanEnumInterfaces(
            client_handle,
            None,
            ctypes.byref(pp_list),
        )
        if ret != ERROR_SUCCESS or not pp_list:
            return False

        try:
            num_items = pp_list.contents.dwNumberOfItems
            if num_items <= 0:
                return False

            class FullInterfaceList(ctypes.Structure):
                _fields_ = [
                    ("dwNumberOfItems", wintypes.DWORD),
                    ("dwIndex", wintypes.DWORD),
                    ("InterfaceInfo", WLAN_INTERFACE_INFO * num_items),
                ]

            full_list = ctypes.cast(pp_list, ctypes.POINTER(FullInterfaceList)).contents
            triggered_any = False

            for i in range(num_items):
                guid = full_list.InterfaceInfo[i].InterfaceGuid
                scan_ret = wlanapi.WlanScan(
                    client_handle,
                    ctypes.byref(guid),
                    None,
                    None,
                    None,
                )
                if scan_ret in (ERROR_SUCCESS, ERROR_NDIS_DOT11_MEDIA_IN_USE):
                    triggered_any = True

            return triggered_any
        finally:
            wlanapi.WlanFreeMemory(pp_list)
    except Exception:
        return False
    finally:
        wlanapi.WlanCloseHandle(client_handle, None)


def _get_fresh_bssids(max_age_seconds: float = _MAX_BSSID_AGE_SECONDS) -> set[str] | None:
    """Return the set of BSSIDs heard within the last `max_age_seconds`.

    Windows' WLAN service caches BSS entries for several minutes even after
    an AP has been powered off or gone out of range. `netsh wlan show networks`
    blindly returns this entire stale cache until the user restarts the interface.
    To immediately drop APs that have been turned off without toggling Wi-Fi,
    we query `WlanGetNetworkBssList` and inspect `ullHostTimestamp`, which
    records the exact system timestamp when the hardware last received a beacon.

    Uses variable-length Information Element (IE) offset walking to correctly
    navigate through all entries without buffer alignment corruption.

    Returns a set of lowercased BSSID strings ("aa:bb:cc:dd:ee:ff") that are
    still actively broadcasting, or None if the API call is unavailable.
    """
    wlanapi, kernel32 = _init_wlan_api()
    if not wlanapi or not kernel32:
        return None

    client_handle = wintypes.HANDLE()
    negotiated_version = wintypes.DWORD()

    try:
        ret = wlanapi.WlanOpenHandle(
            WLAN_API_VERSION_2_0,
            None,
            ctypes.byref(negotiated_version),
            ctypes.byref(client_handle),
        )
        if ret != ERROR_SUCCESS:
            return None
    except Exception:
        return None

    try:
        pp_list = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        ret = wlanapi.WlanEnumInterfaces(
            client_handle,
            None,
            ctypes.byref(pp_list),
        )
        if ret != ERROR_SUCCESS or not pp_list:
            return None

        # Current system time as FILETIME (100ns units since Jan 1 1601 UTC)
        filetime = wintypes.FILETIME()
        kernel32.GetSystemTimeAsFileTime(ctypes.byref(filetime))
        now_ts = (filetime.dwHighDateTime << 32) | filetime.dwLowDateTime
        max_age_ticks = int(max_age_seconds * 10_000_000)

        fresh_bssids: set[str] = set()
        has_any_valid_timestamp = False

        try:
            num_items = pp_list.contents.dwNumberOfItems
            if num_items <= 0:
                return None

            class FullInterfaceList(ctypes.Structure):
                _fields_ = [
                    ("dwNumberOfItems", wintypes.DWORD),
                    ("dwIndex", wintypes.DWORD),
                    ("InterfaceInfo", WLAN_INTERFACE_INFO * num_items),
                ]

            full_list = ctypes.cast(pp_list, ctypes.POINTER(FullInterfaceList)).contents

            for i in range(num_items):
                guid = full_list.InterfaceInfo[i].InterfaceGuid
                pp_bss_list = ctypes.POINTER(WLAN_BSS_LIST)()

                bss_ret = wlanapi.WlanGetNetworkBssList(
                    client_handle,
                    ctypes.byref(guid),
                    None,   # NULL = all SSIDs
                    3,      # dot11_BSS_type_any
                    False,  # bSecurityEnabled
                    None,   # reserved
                    ctypes.byref(pp_bss_list),
                )
                if bss_ret != ERROR_SUCCESS or not pp_bss_list:
                    continue

                try:
                    num_bss = pp_bss_list.contents.dwNumberOfItems
                    if num_bss <= 0:
                        continue

                    # In WLAN_BSS_LIST, each entry has variable length because of
                    # the trailing Information Element (IE) data blob.
                    # Total entry size = entry.ulIeOffset + entry.ulIeSize (aligned to 8 bytes).
                    base_addr = ctypes.cast(pp_bss_list, ctypes.c_void_p).value
                    total_size = pp_bss_list.contents.dwTotalSize
                    curr_offset = 8  # header: dwTotalSize (4) + dwNumberOfItems (4)

                    for j in range(num_bss):
                        if curr_offset + ctypes.sizeof(WLAN_BSS_ENTRY) > total_size:
                            break
                        entry = WLAN_BSS_ENTRY.from_address(base_addr + curr_offset)
                        host_ts = entry.ullHostTimestamp
                        if host_ts > 0:
                            has_any_valid_timestamp = True
                            age_ticks = now_ts - host_ts
                            # Tolerate minor clock skew/jitter if host_ts is slightly ahead
                            if age_ticks < 0 and abs(age_ticks) < 5 * 10_000_000:
                                age_ticks = 0
                            # Keep BSSIDs whose beacon was heard within max_age_seconds
                            if 0 <= age_ticks <= max_age_ticks:
                                bssid = ":".join(f"{b:02x}" for b in entry.dot11Bssid)
                                fresh_bssids.add(bssid.lower())

                        # Advance to next entry safely using variable-length IE offsets
                        if entry.ulIeOffset > 0 and entry.ulIeSize > 0:
                            entry_len = entry.ulIeOffset + entry.ulIeSize
                        else:
                            entry_len = ctypes.sizeof(WLAN_BSS_ENTRY)
                        aligned_len = (entry_len + 7) & ~7
                        curr_offset += aligned_len
                finally:
                    wlanapi.WlanFreeMemory(pp_bss_list)

            # If the driver does not populate host timestamps (all zeros), do not filter
            if not has_any_valid_timestamp:
                return None

            return fresh_bssids
        finally:
            wlanapi.WlanFreeMemory(pp_list)
    except Exception:
        return None
    finally:
        wlanapi.WlanCloseHandle(client_handle, None)


def get_raw_scan_output() -> str:
    """Run `netsh wlan show networks mode=bssid` and return its raw stdout.

    Does NOT trigger a hardware scan itself — call _trigger_scan() first and
    wait _SCAN_SETTLE_SECONDS before calling this, so both netsh and
    _get_fresh_bssids() share the same scan window and their timestamps align.
    """
    result = subprocess.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        creationflags=_NO_WINDOW_FLAGS,
    )
    return result.stdout


def parse_scan_output(raw_output: str) -> list[dict]:
    """Parse the text output of `netsh wlan show networks mode=bssid`.

    netsh groups output by SSID, and within each SSID block lists one or
    more BSSIDs with their own signal/channel/auth info. We flatten this
    into one dict per physical access point (per BSSID).
    """
    networks: list[dict] = []

    # Split into per-SSID blocks. Each block starts with "SSID n : <name>"
    ssid_blocks = re.split(r"\n(?=SSID \d+ : )", raw_output)

    for block in ssid_blocks:
        ssid_match = re.search(r"SSID \d+ : (.*)", block)
        if not ssid_match:
            continue
        ssid = ssid_match.group(1).strip()

        auth_match = re.search(r"Authentication\s*:\s*(.*)", block)
        encryption_match = re.search(r"Encryption\s*:\s*(.*)", block)
        authentication = auth_match.group(1).strip() if auth_match else "Unknown"
        encryption = encryption_match.group(1).strip() if encryption_match else "Unknown"

        # Each BSSID entry starts with "BSSID n : <mac>"
        bssid_entries = re.split(r"\n(?=\s*BSSID \d+\s*:)", block)
        for entry in bssid_entries:
            bssid_match = re.search(r"BSSID \d+\s*:\s*([0-9a-fA-F:]{17})", entry)
            if not bssid_match:
                continue
            bssid = bssid_match.group(1).strip().lower()

            signal_match = re.search(r"Signal\s*:\s*(\d+)%", entry)
            channel_match = re.search(r"Channel\s*:\s*(\d+)", entry)

            signal = int(signal_match.group(1)) if signal_match else 0
            channel = int(channel_match.group(1)) if channel_match else 0

            networks.append(
                {
                    "ssid": ssid,
                    "bssid": bssid,
                    "signal": signal,
                    "channel": channel,
                    "authentication": authentication,
                    "encryption": encryption,
                }
            )

    return networks


def scan() -> list[dict]:
    # 1. Trigger ONE hardware scan and wait for the radio to settle.
    #    Both netsh and WlanGetNetworkBssList then read from the same scan
    #    window, so their timestamps are always perfectly aligned.
    triggered = _trigger_scan()
    if triggered:
        time.sleep(_SCAN_SETTLE_SECONDS)

    # 2. Read netsh output (no extra scan triggered inside).
    raw = get_raw_scan_output()
    networks = parse_scan_output(raw)

    # 3. Filter by BSSID freshness using the timestamps from the same scan.
    fresh_bssids = _get_fresh_bssids()
    if fresh_bssids is not None:
        before_count = len(networks)
        networks = [n for n in networks if n["bssid"] in fresh_bssids]
        dropped_count = before_count - len(networks)
    return networks
