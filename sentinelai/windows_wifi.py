"""Read-only Windows WLAN and network configuration collection. No probing."""
import ctypes as ct
from ctypes import wintypes as wt
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone


class Guid(ct.Structure):
    _fields_ = [('a', wt.DWORD), ('b', wt.WORD), ('c', wt.WORD), ('d', ct.c_ubyte * 8)]


class Interface(ct.Structure):
    _fields_ = [('guid', Guid), ('description', wt.WCHAR * 256), ('state', wt.DWORD)]


class Ssid(ct.Structure):
    _fields_ = [('length', wt.ULONG), ('value', ct.c_ubyte * 32)]


class Association(ct.Structure):
    _fields_ = [('ssid', Ssid), ('bss_type', wt.DWORD), ('bssid', ct.c_ubyte * 6),
                ('phy', wt.DWORD), ('index', wt.ULONG), ('signal', wt.ULONG),
                ('rx', wt.ULONG), ('tx', wt.ULONG)]


class Security(ct.Structure):
    _fields_ = [('enabled', wt.BOOL), ('one_x', wt.BOOL), ('auth', wt.DWORD), ('cipher', wt.DWORD)]


class Connection(ct.Structure):
    _fields_ = [('state', wt.DWORD), ('mode', wt.DWORD), ('profile', wt.WCHAR * 256),
                ('association', Association), ('security', Security)]


AUTH = {1: 'Open', 2: 'Shared', 3: 'WPA', 4: 'WPA-PSK', 5: 'WPA-None',
        6: 'WPA2', 7: 'WPA2-PSK', 8: 'WPA3', 9: 'WPA3-SAE', 10: 'OWE', 11: 'WPA3-Enterprise'}
CIPHER = {0: 'None', 1: 'WEP40', 2: 'TKIP', 4: 'CCMP', 5: 'WEP104',
          8: 'GCMP', 9: 'GCMP256', 10: 'CCMP256', 0x101: 'WEP'}


def wlan_connections():
    if os.name != 'nt':
        raise OSError('Public Wi-Fi collection requires Windows with a Wi-Fi adapter.')
    api = ct.WinDLL('wlanapi.dll', winmode=0x800)  # LOAD_LIBRARY_SEARCH_SYSTEM32
    api.WlanOpenHandle.argtypes = [wt.DWORD, ct.c_void_p, ct.POINTER(wt.DWORD), ct.POINTER(wt.HANDLE)]
    api.WlanOpenHandle.restype = wt.DWORD
    api.WlanEnumInterfaces.argtypes = [wt.HANDLE, ct.c_void_p, ct.POINTER(ct.c_void_p)]
    api.WlanEnumInterfaces.restype = wt.DWORD
    api.WlanQueryInterface.argtypes = [wt.HANDLE, ct.POINTER(Guid), wt.DWORD, ct.c_void_p,
                                      ct.POINTER(wt.DWORD), ct.POINTER(ct.c_void_p), ct.c_void_p]
    api.WlanQueryInterface.restype = wt.DWORD
    api.WlanFreeMemory.argtypes = [ct.c_void_p]
    api.WlanFreeMemory.restype = None
    api.WlanCloseHandle.argtypes = [wt.HANDLE, ct.c_void_p]
    api.WlanCloseHandle.restype = wt.DWORD
    handle, version = wt.HANDLE(), wt.DWORD()

    def check(code):
        if code:
            message = ('Access denied. Check Location access for desktop apps, WLAN AutoConfig, and device policy; restricted execution may also block collection.'
                       if code == 5 else ct.FormatError(code).strip())
            raise OSError(f'Windows WLAN error {code}: {message}')

    check(api.WlanOpenHandle(2, None, ct.byref(version), ct.byref(handle)))
    listing = ct.c_void_p()
    try:
        check(api.WlanEnumInterfaces(handle, None, ct.byref(listing)))
        count = ct.cast(listing, ct.POINTER(wt.DWORD))[0]
        if count > 256:
            raise OSError('Invalid WLAN interface list')
        items = (Interface * count).from_address(listing.value + 8)
        result = []
        for item in items:
            if item.state != 1:  # wlan_interface_state_connected
                continue
            data, size = ct.c_void_p(), wt.DWORD()
            try:
                check(api.WlanQueryInterface(handle, ct.byref(item.guid), 7, None,
                                             ct.byref(size), ct.byref(data), None))
                if size.value < ct.sizeof(Connection):
                    raise OSError('Incomplete WLAN connection attributes')
                connection = ct.cast(data, ct.POINTER(Connection)).contents
                association, security = connection.association, connection.security
                if association.ssid.length > 32:
                    raise OSError('Invalid WLAN SSID length')
                result.append(dict(interface_id=str(uuid.UUID(bytes_le=bytes(item.guid))),
                    interface=item.description, ssid=bytes(association.ssid.value[:association.ssid.length]).decode('utf-8', 'replace'),
                    bssid=':'.join(f'{v:02x}' for v in association.bssid), signal=int(association.signal),
                    security_enabled=bool(security.enabled), auth=AUTH.get(security.auth, f'Unknown({security.auth})'),
                    cipher=CIPHER.get(security.cipher, f'Unknown({security.cipher})')))
            finally:
                if data.value:
                    api.WlanFreeMemory(data)
        return result
    finally:
        if listing.value:
            api.WlanFreeMemory(listing)
        api.WlanCloseHandle(handle, None)


CONFIG_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$warnings = @()
$adapters = @()
try {
  $configs = @(Get-NetIPConfiguration -All -ErrorAction Stop)
  foreach ($c in $configs) {
    $category = $null
    try { $category = [string](Get-NetConnectionProfile -InterfaceIndex $c.InterfaceIndex -ErrorAction Stop).NetworkCategory }
    catch { $warnings += 'Network profile category unavailable.' }
    $adapters += [pscustomobject]@{
      interface_id = [string]$c.NetAdapter.InterfaceGuid
      ip = @($c.IPv4Address.IPAddress) | Select-Object -First 1
      gateway = @($c.IPv4DefaultGateway.NextHop) | Select-Object -First 1
      dns = @($c.DNSServer.ServerAddresses | Sort-Object -Unique)
      category = $category
    }
  }
} catch { $warnings += 'Network configuration unavailable: check Windows permissions and network services.' }
$firewall = $null
try {
  $enabled = [int](Get-NetFirewallProfile -Name Public -PolicyStore ActiveStore -ErrorAction Stop).Enabled
  if ($enabled -eq 1) { $firewall = $true }
  elseif ($enabled -eq 0) { $firewall = $false }
  else { $warnings += 'Effective Public firewall state is unknown.' }
}
catch { $warnings += 'Public firewall profile status unavailable.' }
[pscustomobject]@{ adapters=@($adapters); public_firewall_enabled=$firewall; warnings=@($warnings) } | ConvertTo-Json -Depth 6 -Compress
'''


def collect_snapshot():
    networks = wlan_connections()
    warnings = []
    config = {}
    if networks:
        try:
            result = subprocess.run(['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', CONFIG_SCRIPT],
                capture_output=True, encoding='utf-8', errors='replace', timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            if result.returncode:
                raise OSError('Windows network configuration query failed')
            config = json.loads(result.stdout.lstrip('\ufeff'))
            warnings.extend(config.get('warnings', []))
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            warnings.append(f'Network configuration unavailable: {exc}')
        adapters = {str(a.get('interface_id', '')).strip('{}').lower(): a for a in config.get('adapters', [])}
        for network in networks:
            adapter = adapters.get(network['interface_id'])
            if adapter:
                network.update({k: adapter.get(k) for k in ['ip', 'gateway', 'dns', 'category']})
            else:
                warnings.append('IP, gateway and DNS unavailable for a connected Wi-Fi adapter.')
    return dict(timestamp=datetime.now(timezone.utc).isoformat(), networks=networks,
                public_firewall_enabled=config.get('public_firewall_enabled'), warnings=warnings)
