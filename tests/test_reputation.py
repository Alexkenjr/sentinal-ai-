import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from sentinelai.core import Store
from sentinelai import reputation as rep

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


class ReputationTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.addCleanup(self.store.close)
        self.clock = patch('sentinelai.reputation.utc_now', return_value=NOW)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def test_private_and_documentation_ips_never_leave_device(self):
        with patch('sentinelai.reputation.fetch') as fetch:
            for address in ['192.168.1.1', '127.0.0.1', '192.0.2.1', '::1', 'ff02::1', '100.64.0.1']:
                self.assertEqual(rep.lookup(self.store, address)['status'], 'not_applicable')
            fetch.assert_not_called()

    def test_missing_keys_are_unavailable_not_clean(self):
        with patch.dict(os.environ, {'ABUSEIPDB_API_KEY': '', 'VIRUSTOTAL_API_KEY': ''}):
            result = rep.lookup(self.store, '8.8.8.8')
            self.assertEqual(result['status'], 'unavailable')
            self.assertIsNone(result['fetched_at'])

    def test_abuseipdb_reason_dates_cache_and_secret_exclusion(self):
        raw = {'data': dict(ipAddress='8.8.8.8', totalReports=12, abuseConfidenceScore=75,
                            lastReportedAt='2026-10-20T12:00:00Z')}
        with patch.dict(os.environ, {'ABUSEIPDB_API_KEY': 'SECRET-TEST-KEY'}), \
             patch('sentinelai.reputation.request_json', return_value=raw) as request:
            first = rep.lookup(self.store, '8.8.8.8')
            second = rep.lookup(self.store, '8.8.8.8')
            self.assertFalse(first['cached'])
            self.assertTrue(second['cached'])
            self.assertEqual(request.call_count, 1)
            self.assertIn('12 report', first['reason_mn'])
            self.assertEqual(first['provider_updated_at'], '2026-10-20T12:00:00+00:00')
            self.assertEqual(first['fetched_at'], NOW.isoformat())
            saved = self.store.db.execute('SELECT data FROM reputation_cache').fetchone()[0]
            self.assertNotIn('SECRET-TEST-KEY', saved)

    def test_virustotal_flags_and_unknown_update(self):
        raw = {'data': {'id': '8.8.8.8', 'attributes': {'last_analysis_stats':
               dict(malicious=2, suspicious=1, harmless=40, undetected=20)}}}
        with patch.dict(os.environ, {'VIRUSTOTAL_API_KEY': 'TEST'}), patch('sentinelai.reputation.request_json', return_value=raw):
            result = rep.lookup(self.store, '8.8.8.8', 'virustotal')
        self.assertEqual(result['status'], 'flagged')
        self.assertEqual(result['freshness'], 'unknown')
        self.assertIsNone(result['provider_updated_at'])

    def test_provider_error_keeps_previous_data_and_original_dates(self):
        result = dict(ip='8.8.8.8', provider='abuseipdb', status='reported', reason_mn='Synthetic fixture',
                      fetched_at=(NOW-timedelta(days=2)).isoformat(), provider_updated_at=(NOW-timedelta(days=10)).isoformat())
        rep.ensure_schema(self.store)
        self.store.db.execute('INSERT INTO reputation_cache VALUES (?,?,?)', ('8.8.8.8','abuseipdb',json.dumps(result)))
        self.store.db.commit()
        with patch('sentinelai.reputation.fetch', side_effect=rep.ProviderError('HTTP 429')):
            value = rep.lookup(self.store, '8.8.8.8', refresh=True)
        self.assertTrue(value['refresh_failed'])
        self.assertEqual(value['freshness'], 'refresh_failed')
        self.assertEqual(value['fetched_at'], result['fetched_at'])
        self.assertEqual(value['status'], 'reported')

    def test_wrong_ip_and_malformed_dates_not_cached(self):
        for raw in [dict(ipAddress='1.1.1.1', totalReports=0, abuseConfidenceScore=0),
                    dict(ipAddress='8.8.8.8', totalReports=1, abuseConfidenceScore=30, lastReportedAt='bad')]:
            with patch.dict(os.environ, {'ABUSEIPDB_API_KEY': 'TEST'}), patch('sentinelai.reputation.request_json', return_value={'data': raw}):
                self.assertEqual(rep.lookup(self.store, '8.8.8.8', refresh=True)['status'], 'unavailable')
        self.assertEqual(rep.cached(self.store, '8.8.8.8'), [])

    def test_http_429_does_not_leak_key_or_retry(self):
        error = HTTPError('https://api.abuseipdb.com', 429, 'SECRET-TEST-KEY', {}, None)
        with patch('sentinelai.reputation.build_opener') as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(rep.ProviderError) as caught:
                rep.request_json('https://api.abuseipdb.com', {'Key': 'SECRET-TEST-KEY'})
            self.assertNotIn('SECRET-TEST-KEY', str(caught.exception))
            self.assertIn('429', str(caught.exception))
            self.assertEqual(opener.return_value.open.call_count, 1)
        self.assertIsNone(rep.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.invalid'))
