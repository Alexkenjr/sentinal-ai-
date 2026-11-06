"""Generate local Nmap inventory and Wireshark-compatible synthetic PCAP/CSV fixtures."""
import csv
import ipaddress
import json
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from .importers import convert, import_nmap
from .service import export_alerts
from .simulation import Simulation, fresh_directory

FIELDS = ['frame.time_epoch', 'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst',
          'tcp.dstport', 'udp.dstport', 'tcp.flags.syn', 'tcp.flags.ack']


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data)//2}H', data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def packet(src, dst, port, index):
    source, target = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    tcp = struct.pack('!HHIIBBHHH', 40000 + index, port, index, 0, 0x50, 2, 64240, 0, 0)
    tcp_sum = checksum(source + target + struct.pack('!BBH', 0, 6, len(tcp)) + tcp)
    tcp = tcp[:16] + struct.pack('!H', tcp_sum) + tcp[18:]
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, index, 0x4000, 64, 6, 0, source, target)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return bytes.fromhex('0200000000020200000000010800') + header + tcp


def generate(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    start = int(datetime.now(timezone.utc).timestamp())
    rows = []
    for host in range(1, 51):
        values = range(1000, 1008) if host <= 5 else [443]
        for port in values:
            rows.append(dict(zip(FIELDS, [str(start + len(rows)), f'192.0.2.{host}', '198.51.100.80', '', '', str(port), '', '1', '0'])))
    with (directory / 'wireshark.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    with (directory / 'wireshark.pcap').open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, row in enumerate(rows):
            data = packet(row['ip.src'], row['ip.dst'], int(row['tcp.dstport']), i)
            stream.write(struct.pack('<IIII', int(row['frame.time_epoch']), 0, len(data), len(data)) + data)
    zeek = [dict(ts=float(row['frame.time_epoch']), uid=f'SYNTHETIC{i}',
        **{'id.orig_h': row['ip.src'], 'id.orig_p': 40000+i, 'id.resp_h': row['ip.dst'],
           'id.resp_p': int(row['tcp.dstport']), 'proto': 'tcp', 'conn_state': 'S0'}) for i, row in enumerate(rows)]
    (directory / 'zeek_conn.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in zeek), encoding='utf-8')
    nmap = ET.Element('nmaprun', scanner='nmap', start=str(start), version='synthetic', args='SYNTHETIC OFFLINE INVENTORY; no scanner executed')
    for host in range(1, 51):
        node = ET.SubElement(nmap, 'host')
        ET.SubElement(node, 'status', state='up', reason='synthetic')
        ET.SubElement(node, 'address', addr=f'192.0.2.{host}', addrtype='ipv4')
        node_ports = ET.SubElement(node, 'ports')
        for number, name in [(22, 'ssh'), (80, 'http'), (443, 'https')]:
            port = ET.SubElement(node_ports, 'port', protocol='tcp', portid=str(number))
            ET.SubElement(port, 'state', state='open', reason='synthetic')
            ET.SubElement(port, 'service', name=name, method='table', conf='3')
    ET.ElementTree(nmap).write(directory / 'nmap.xml', encoding='utf-8', xml_declaration=True)
    (directory / 'ips.txt').write_text(''.join(f'192.0.2.{i}\n' for i in range(1, 51)), encoding='utf-8')
    manifest = dict(synthetic=True, executed_tools=[], source_ips=50, packet_records=len(rows),
        expected_port_scan_alerts=5, nmap_hosts=50, nmap_open_ports=150,
        note='Nmap inventory and packet timeline are independent fixtures, not a claim about a real scan.')
    (directory / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return directory


class ToolSimulation(Simulation):
    def __init__(self, directory):
        self.directory = generate(directory)
        converted = convert(self.directory / 'wireshark.csv', 'tshark', self.directory / 'normalized_full.jsonl')
        self.plan = [('SYNTHETIC scan-like TCP SYN sequence' if i < 40 else 'SYNTHETIC normal single-port connections', event)
                     for i, event in enumerate(converted['events'])]
        self.path = self.directory / 'events.jsonl'
        self.path.write_bytes(b'')
        self.db = self.directory / 'alerts.sqlite3'
        self.position, self.hosts = 0, 50
        self.ips = [f'192.0.2.{i}' for i in range(1, 51)]

    def report(self, store):
        alerts = store.list_alerts()
        inventory = import_nmap(self.directory / 'nmap.xml')
        observed = sorted((a['rule'], a['src_ip']) for a in alerts)
        expected = sorted(('port_scan', f'192.0.2.{i}') for i in range(1, 6))
        result = dict(synthetic=True, complete=self.complete, events_written=self.position,
            unique_ips=len({e['src_ip'] for _, e in self.plan[:self.position]}), expected_unique_ips=50,
            expected_alert_count=5, expected_rules=['port_scan']*5, observed_rules=[a['rule'] for a in alerts],
            nmap_hosts=inventory['host_count'], nmap_open_ports=inventory['open_ports'],
            passed=self.complete and observed == expected and inventory['host_count'] == 50 and inventory['open_ports'] == 150)
        export_alerts(alerts, self.directory / 'alerts.csv')
        export_alerts(alerts, self.directory / 'alerts.json')
        (self.directory / 'report.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        return result


def run(directory, interval=0.1):
    from .simulation import run_session, validate_interval
    validate_interval(interval)
    return run_session(ToolSimulation(fresh_directory(directory)), interval)
