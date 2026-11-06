"""Shared validation and matching for IP addresses, networks and destination ports."""
import ipaddress
import json


def network(value):
    if not value:
        return None
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        raise ValueError('IP filter must be an IPv4/IPv6 address or CIDR network') from None


def ports(value):
    if value in (None, ''):
        return ()
    result = []
    try:
        for item in str(value).split(','):
            bounds = item.strip().split('-')
            if len(bounds) > 2:
                raise ValueError()
            lo, hi = int(bounds[0]), int(bounds[-1])
            if not 1 <= lo <= hi <= 65535:
                raise ValueError()
            result.append((lo, hi))
    except (ValueError, TypeError):
        raise ValueError('Port filter must be 1..65535, a comma-separated list, or ranges such as 1000-1010') from None
    return tuple(result)


def ip_matches(address, cidr):
    if not cidr:
        return True
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return False


def port_matches(value, ranges):
    try:
        return not ranges or any(lo <= int(value) <= hi for lo, hi in ranges)
    except (TypeError, ValueError):
        return False


def validate(src_ip=None, dst_ip=None, port=None, protocol=None, source=None):
    result = dict(src_ip=network(src_ip), dst_ip=network(dst_ip), port=port or None,
                  protocol=protocol or None, source=source or None)
    ports(port)
    if protocol and protocol not in ('tcp', 'udp'):
        raise ValueError('Protocol must be tcp or udp')
    if source and source not in ('jsonl', 'tshark', 'zeek', 'suricata', 'windows_wifi'):
        raise ValueError('Unknown telemetry source')
    return result


def evidence_matches(raw, dst_ip, port, protocol, source):
    try:
        evidence = json.loads(raw)
        destinations = evidence.get('destinations', [evidence.get('dst_ip')])
        values = evidence.get('dst_ports', [evidence.get('dst_port')])
        protocols = evidence.get('protocols', [evidence.get('protocol')])
        origin = evidence.get('source') or ('windows_wifi' if evidence.get('source_kind') == 'local_device' else 'jsonl')
        if evidence.get('flows') and any((dst_ip, port, protocol)):
            return int((not source or source == origin) and any(
                (not dst_ip or ip_matches(flow.get('dst_ip'), dst_ip)) and
                (not port or port_matches(flow.get('dst_port'), ports(port))) and
                (not protocol or flow.get('protocol') == protocol) for flow in evidence['flows']))
        return int((not dst_ip or any(ip_matches(ip, dst_ip) for ip in destinations)) and
                   (not port or any(port_matches(p, ports(port)) for p in values)) and
                   (not protocol or protocol in protocols) and (not source or source == origin))
    except (TypeError, ValueError, AttributeError):
        return 0
