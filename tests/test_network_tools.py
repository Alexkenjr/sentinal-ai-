import csv
import json
import struct
import tempfile
import unittest
from pathlib import Path
from sentinelai.core import Store, event_from_line
from sentinelai.filters import validate
from sentinelai.importers import convert, import_nmap, import_tshark, import_zeek, inventory_rows
from sentinelai.service import MonitorSession
from sentinelai.tool_simulation import ToolSimulation, generate, checksum

ROOT = Path(__file__).resolve().parents[1]


class NetworkToolTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def test_tools_simulation_and_ip_port_protocol_filters(self):
        simulation = ToolSimulation(self.directory / 'demo')
        session = MonitorSession(simulation.path, simulation.db)
        try:
            while not simulation.complete:
                simulation.step()
                session.poll()
            report = simulation.report(session.store)
            self.assertTrue(report['passed'])
            self.assertEqual(report['unique_ips'], 50)
            self.assertEqual(report['events_written'], 85)
            rows = session.store.list_alerts(src_ip='192.0.2.1', dst_ip='198.51.100.0/24',
                port='22,1000-1007', protocol='tcp', source='tshark')
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['src_ip'], '192.0.2.1')
            self.assertEqual(session.store.list_alerts(port='443'), [])
            self.assertEqual(len(session.store.list_alerts(src_ip='192.0.2.0/24', limit=2)), 2)
            self.assertEqual(session.store.list_alerts(protocol='udp'), [])
        finally:
            session.close()

    def test_nmap_inventory_does_not_create_attack_alerts(self):
        directory = generate(self.directory / 'examples')
        report = convert(directory / 'nmap.xml', 'nmap', self.directory / 'inventory.json')
        self.assertEqual(report['host_count'], 50)
        self.assertEqual(report['open_ports'], 150)
        self.assertEqual(len(inventory_rows(report, ip='192.0.2.1', port='22,443')), 2)
        self.assertNotIn('events', report)
        self.assertFalse((directory / 'alerts.sqlite3').exists())

    def test_zeek_and_tshark_metadata_agree(self):
        directory = generate(self.directory / 'examples')
        tshark, zeek = import_tshark(directory / 'wireshark.csv'), import_zeek(directory / 'zeek_conn.jsonl')
        self.assertEqual(tshark['invalid'], 0)
        self.assertEqual(zeek['invalid'], 0)
        self.assertEqual(len(tshark['events']), 85)
        for first, second in zip(tshark['events'], zeek['events']):
            self.assertEqual({k: v for k, v in first.items() if k != 'source'},
                             {k: v for k, v in second.items() if k != 'source'})

    def test_pcap_packet_lengths_and_checksums(self):
        directory = generate(self.directory / 'examples')
        raw = (directory / 'wireshark.pcap').read_bytes()
        self.assertEqual(struct.unpack('<IHHIIII', raw[:24]), (0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        offset, count = 24, 0
        while offset < len(raw):
            _, _, length, original = struct.unpack('<IIII', raw[offset:offset+16])
            self.assertEqual(length, original)
            data = raw[offset+16:offset+16+length]
            self.assertEqual(len(data), 54)
            ip, tcp = data[14:34], data[34:]
            self.assertEqual(checksum(ip), 0)
            pseudo = ip[12:20] + struct.pack('!BBH', 0, 6, len(tcp))
            self.assertEqual(checksum(pseudo + tcp), 0)
            count += 1
            offset += 16+length
        self.assertEqual(count, 85)

    def test_invalid_filters_fail_clearly(self):
        for kwargs in [dict(src_ip='wrong'), dict(port='0'), dict(port='443-22'), dict(port='65536'), dict(protocol='icmp')]:
            with self.assertRaises(ValueError):
                validate(**kwargs)
        self.assertEqual(validate(src_ip='2001:db8::1')['src_ip'], '2001:db8::1/128')

    def test_optional_metadata_validation_and_ipv6_source_filter(self):
        value = dict(timestamp='2026-10-20T12:00:00Z', event_type='connection', src_ip='2001:db8::1', dst_port=443)
        for fields in [dict(protocol=[]), dict(dst_ip=1234), dict(source={})]:
            with self.assertRaises(ValueError):
                event_from_line(json.dumps({**value, **fields}))
        self.assertEqual(event_from_line(json.dumps({**value, 'protocol': 'TCP'}))['protocol'], 'tcp')
        store = Store(':memory:')
        try:
            store.add(dict(timestamp='2026-10-20T12:00:00+00:00', rule='port_scan', src_ip='2001:db8::1',
                severity='medium', score=50, evidence={}), 0)
            self.assertEqual(len(store.list_alerts(src_ip='2001:db8::/32')), 1)
            self.assertEqual(store.list_alerts(src_ip='192.0.2.0/24'), [])
        finally:
            store.close()

    def test_combined_destination_and_port_must_match_same_flow(self):
        store = Store(':memory:')
        try:
            store.add(dict(timestamp='2026-10-20T12:00:00+00:00', rule='port_scan', src_ip='192.0.2.1',
                severity='medium', score=50, evidence={'source': 'tshark', 'flows': [
                    dict(dst_ip='198.51.100.1', dst_port=22, protocol='tcp'),
                    dict(dst_ip='198.51.100.2', dst_port=443, protocol='tcp')]}), 0)
            self.assertEqual(store.list_alerts(dst_ip='198.51.100.1', port='443'), [])
            self.assertEqual(len(store.list_alerts(dst_ip='198.51.100.1', port='22')), 1)
        finally:
            store.close()

    def test_tshark_synack_and_invalid_rows_not_counted(self):
        path = self.directory / 'packets.csv'
        fields = ['frame.time_epoch', 'ip.src', 'ip.dst', 'tcp.dstport', 'udp.dstport', 'tcp.flags.syn', 'tcp.flags.ack']
        with path.open('w', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(fields)
            writer.writerow(['1792497600', '192.0.2.1', '198.51.100.1', '80', '', '1', '0'])
            writer.writerow(['1792497601', '198.51.100.1', '192.0.2.1', '40000', '', '1', '1'])
            writer.writerow(['NaN', '192.0.2.1', '198.51.100.1', '81', '', '1', '0'])
        result = import_tshark(path)
        self.assertEqual((len(result['events']), result['skipped'], result['invalid']), (1, 1, 1))

    def test_invalid_xml_and_inplace_import_rejected(self):
        path = self.directory / 'bad.xml'
        for text in ['<bad/>', '<nmaprun>', '<!DOCTYPE nmaprun [<!ENTITY x "test">]><nmaprun/>']:
            path.write_text(text)
            with self.assertRaises(ValueError):
                import_nmap(path)
        with self.assertRaises(ValueError):
            convert(path, 'nmap', path)
