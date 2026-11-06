"""Bounded offline format adapters. No scanner, packet capture or external process."""
import csv
import io
import ipaddress
import json
import math
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET
from .core import event_from_line
from .filters import network, ports, ip_matches, port_matches

MAX_BYTES = 20 * 1024 * 1024
MAX_RECORDS = 100000


def read_bytes(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('Import is limited to 20 MiB; split larger files first')
    return data


def read_file(path):
    return read_bytes(path).decode('utf-8-sig')


def timestamp(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError('Invalid epoch timestamp')
    return datetime.fromtimestamp(number, timezone.utc).isoformat()


def normalized(value, source):
    value['source'] = source
    value['dst_ip'] = str(ipaddress.ip_address(value['dst_ip']))
    value['protocol'] = value['protocol'].lower()
    if value['protocol'] not in ('tcp', 'udp'):
        return None
    value['dst_port'] = int(value['dst_port'])
    event = event_from_line(json.dumps(value))
    del event['_time']
    return event


def import_tshark(path):
    reader = csv.DictReader(io.StringIO(read_file(path)))
    required = {'frame.time_epoch', 'ip.src', 'ip.dst', 'tcp.dstport', 'udp.dstport'}
    if not reader.fieldnames or not required <= set(reader.fieldnames):
        raise ValueError('TShark CSV requires frame.time_epoch, ip.src, ip.dst, tcp.dstport, udp.dstport headers; see INTEGRATIONS.md')
    events, invalid, skipped = [], 0, 0
    for index, row in enumerate(reader):
        if index >= MAX_RECORDS:
            raise ValueError('Too many import records (maximum 100000)')
        try:
            src = row.get('ip.src') or row.get('ipv6.src')
            dst = row.get('ip.dst') or row.get('ipv6.dst')
            tcp, udp = row.get('tcp.dstport'), row.get('udp.dstport')
            if not src or not dst or not (tcp or udp):
                skipped += 1
                continue
            # A CSV field containing multiple encapsulated values is ambiguous.
            if ',' in src or ',' in dst or (tcp and udp):
                raise ValueError('Ambiguous packet addresses/ports')
            # TCP scan detection uses initial SYN only, avoiding reverse SYN/ACK and payload responses.
            if tcp and {'tcp.flags.syn', 'tcp.flags.ack'} <= set(reader.fieldnames):
                if row.get('tcp.flags.syn') != '1' or row.get('tcp.flags.ack') != '0':
                    skipped += 1
                    continue
            event = normalized(dict(timestamp=timestamp(row['frame.time_epoch']), event_type='connection',
                src_ip=src, dst_ip=dst, dst_port=tcp or udp, protocol='tcp' if tcp else 'udp'), 'tshark')
            events.append(event)
        except (TypeError, ValueError, KeyError, OverflowError, OSError):
            invalid += 1
    events.sort(key=lambda e: e['timestamp'])
    return dict(events=events, invalid=invalid, skipped=skipped, source='tshark',
                warning='Packet metadata only. Without SYN/ACK flag columns, TCP direction cannot be filtered reliably.'
                if not {'tcp.flags.syn', 'tcp.flags.ack'} <= set(reader.fieldnames) else '')


def import_zeek(path):
    events, invalid, skipped = [], 0, 0
    for index, line in enumerate(read_file(path).splitlines()):
        if index >= MAX_RECORDS:
            raise ValueError('Too many import records (maximum 100000)')
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            if row.get('proto') not in ('tcp', 'udp'):
                skipped += 1
                continue
            events.append(normalized(dict(timestamp=timestamp(row['ts']), event_type='connection',
                src_ip=row['id.orig_h'], dst_ip=row['id.resp_h'], dst_port=row['id.resp_p'], protocol=row['proto']), 'zeek'))
        except (TypeError, ValueError, KeyError, AttributeError, OverflowError, OSError):
            invalid += 1
    events.sort(key=lambda e: e['timestamp'])
    return dict(events=events, invalid=invalid, skipped=skipped, source='zeek', warning='JSON conn.log only; Zeek TSV is not supported.')


def import_nmap(path):
    text = read_file(path)
    if '<!ENTITY' in text:
        raise ValueError('XML entity declarations are not accepted')
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f'Invalid Nmap XML: {exc}') from None
    if root.tag != 'nmaprun':
        raise ValueError('Expected an Nmap nmaprun XML document')
    hosts = []
    for node in root.findall('host'):
        addresses = [a.get('addr') for a in node.findall('address') if a.get('addrtype') in ('ipv4', 'ipv6')]
        if not addresses:
            continue
        address = str(ipaddress.ip_address(addresses[0]))
        services = []
        for port in node.findall('./ports/port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            value = int(port.get('portid', '0'))
            protocol = port.get('protocol')
            if not 1 <= value <= 65535 or protocol not in ('tcp', 'udp'):
                raise ValueError('Invalid Nmap port/protocol')
            service = port.find('service')
            services.append(dict(port=value, protocol=protocol, service=service.get('name', '') if service is not None else ''))
        state = node.find('status')
        hosts.append(dict(ip=address, state=state.get('state', 'unknown') if state is not None else 'unknown', ports=services))
    return dict(kind='inventory', source='nmap', hosts=hosts, host_count=len(hosts),
                open_ports=sum(len(h['ports']) for h in hosts),
                warning='Inventory of scanned targets; not evidence that these hosts attacked anyone.')


def import_suricata(path):
    raw = read_bytes(path)
    text = raw.decode('utf-8-sig')
    file_hash = hashlib.sha256(raw).hexdigest()
    events, invalid, skipped = [], 0, 0
    for index, line in enumerate(text.splitlines()):
        if index >= MAX_RECORDS:
            raise ValueError('Too many import records (maximum 100000)')
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            kind = row['event_type']
            if kind not in ('alert', 'flow'):
                skipped += 1
                continue
            protocol = str(row.get('proto', '')).lower()
            if protocol == 'ipv6-icmp':
                protocol = 'icmpv6'
            if kind == 'flow' and protocol not in ('tcp', 'udp'):
                skipped += 1
                continue
            value = dict(timestamp=row['timestamp'], src_ip=row['src_ip'], dst_ip=row['dest_ip'],
                source='suricata', event_type='ids_alert' if kind == 'alert' else 'connection',
                event_id=hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest(),
                provenance=dict(format='suricata_eve', file_sha256=file_hash, line=index+1))
            for original, target in [('src_port','src_port'),('dest_port','dst_port'),('flow_id','flow_id'),('community_id','community_id')]:
                if row.get(original) is not None:
                    value[target] = row[original]
            if protocol:
                value['protocol'] = protocol
            if kind == 'alert':
                alert = row['alert']
                value.update(signature_id=alert['signature_id'], signature=alert['signature'],
                    ids_severity=alert['severity'], gid=alert.get('gid', 1), rev=alert.get('rev'),
                    category=alert.get('category'), action=alert.get('action'))
            event = event_from_line(json.dumps(value))
            del event['_time']
            events.append(event)
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError, OSError):
            invalid += 1
    events.sort(key=lambda event: event['timestamp'])
    return dict(events=events, invalid=invalid, skipped=skipped, source='suricata',
        warning='EVE alert signatures are external IDS indicators, not confirmed compromise. Flow events and alerts are kept separate.')


def inventory_rows(report, ip=None, port=None, protocol=None):
    cidr, ranges = network(ip), ports(port)
    return [dict(ip=host['ip'], **service) for host in report['hosts'] if ip_matches(host['ip'], cidr)
            for service in host['ports'] if port_matches(service['port'], ranges) and
            (not protocol or service['protocol'] == protocol)]


def export_inventory(rows, path):
    path = Path(path)
    if path.suffix.lower() == '.csv':
        with path.open('w', encoding='utf-8', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=['ip', 'port', 'protocol', 'service'])
            writer.writeheader()
            for row in rows:
                safe = {key: "'" + value if isinstance(value, str) and value.startswith(('=', '+', '-', '@', '\t', '\r')) else value
                        for key, value in row.items()}
                writer.writerow(safe)
    else:
        path.write_text(json.dumps(rows, indent=2) + '\n', encoding='utf-8')


def convert(path, format, output):
    if Path(path).resolve() == Path(output).resolve():
        raise ValueError('Import output must differ from the input file')
    if format == 'nmap':
        result = import_nmap(path)
    elif format == 'tshark':
        result = import_tshark(path)
    elif format == 'zeek':
        result = import_zeek(path)
    elif format == 'suricata':
        result = import_suricata(path)
    else:
        raise ValueError('Unknown import format')
    if format != 'nmap' and not result['events']:
        raise ValueError(f'No usable normalized records: invalid={result["invalid"]}, skipped={result["skipped"]}')
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if format == 'nmap':
        output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    else:
        output.write_text(''.join(json.dumps(e) + '\n' for e in result['events']), encoding='utf-8')
    return result
