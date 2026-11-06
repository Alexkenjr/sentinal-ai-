"""Desktop regressions. Requires Tk and a graphical Windows/Linux session."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import tkinter as tk
import time
from sentinelai.core import Store
from sentinelai.gui import Application
from sentinelai.wifi import WifiSession
from sentinelai.filters import validate as validate_filters

ROOT = Path(__file__).resolve().parents[1]


class DesktopRegressionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(directory.cleanup)
        self.root = tk.Tk()
        self.root.attributes('-alpha', 0)
        self.app = Application(self.root, directory.name)
        self.addCleanup(self.app.close)
        self.root.geometry('900x620')
        self.root.update()

    def test_refresh_keeps_rows_scroll_selection_and_emits_no_selection_events(self):
        app = self.app
        app.demo()
        store = Store(app.db.get())
        try:
            for i in range(80):
                store.add(dict(timestamp='2026-01-02T00:00:00+00:00', rule='port_scan',
                    src_ip=f'192.0.2.{100+i}', severity='medium', score=50, evidence={'count': 8}), 0)
        finally:
            store.close()
        app.refresh()
        self.root.update()
        app.table.yview_moveto(0.5)
        app.table.selection_set('40')
        app.table.focus('40')
        self.root.update()
        before = app.table.yview()
        selection_events = []
        app.table.bind('<<TreeviewSelect>>', lambda _: selection_events.append(True), add='+')
        with patch.object(app.table, 'delete', wraps=app.table.delete) as deletion:
            for _ in range(5):
                app.refresh()
                self.root.update()
            self.assertEqual(deletion.call_count, 0)
        self.assertEqual(app.table.selection(), ('40',))
        self.assertEqual(app.table.focus(), '40')
        self.assertEqual(app.table.yview(), before)
        self.assertEqual(selection_events, [])

    def test_triage_immediately_obeys_filter(self):
        app = self.app
        app.demo()
        app.status_filter.set('new')
        app.refresh()
        app.table.selection_set('1')
        app.triage('acknowledged')
        self.assertNotIn('1', app.rows)
        self.assertFalse(app.table.exists('1'))
        app.status_filter.set('acknowledged')
        app.refresh()
        self.assertEqual(list(app.rows), ['1'])

    def test_demo_resets_filters_and_stage(self):
        app = self.app
        app.severity.set('high')
        app.status_filter.set('dismissed')
        app.attack_filter.set('Wi-Fi network change')
        app.demo()
        self.assertEqual(len(app.rows), 3)
        self.assertEqual(app.severity.get(), 'all')
        self.assertEqual(app.status_filter.get(), 'all')
        self.assertEqual(app.attack_filter.get(), 'All types')
        self.assertIn('Synthetic snapshot', app.stage.get())
        self.assertEqual({name: value.get() for name, value in app.metrics.items()},
                         {'EVENTS': '14', 'ALERTS': '3', 'CRITICAL': '1'})
        app.severity.set('critical')
        app.refresh()
        self.assertEqual(app.metrics['ALERTS'].get(), '1')
        self.assertEqual(app.metrics['CRITICAL'].get(), '1')

    def test_attack_filter_changes_visible_rows_and_counter(self):
        app = self.app
        app.demo()
        app.attack_filter.set('Port scanning')
        app.refresh()
        self.assertEqual(len(app.rows), 1)
        row = next(iter(app.rows.values()))
        self.assertEqual(row['rule'], 'port_scan')
        self.assertEqual(row['attack_type'], 'port_scan')
        self.assertEqual(app.metrics['ALERTS'].get(), '1')
        app.attack_filter.set('Wi-Fi security risk')
        app.refresh()
        self.assertEqual(app.rows, {})
        app.attack_filter.set('All types')
        app.refresh()
        self.assertEqual(len(app.rows), 3)

    def test_investigation_windows_and_reputation_are_opt_in(self):
        app = self.app
        app.simulate_investigation()
        while app.session:
            if app.timer is not None:
                self.root.after_cancel(app.timer)
                app.timer = None
            app.tick()
        self.assertEqual(len(app.rows), 4)
        app.table.selection_set('3')
        with patch('sentinelai.reputation.request_json') as api:
            explanation = app.show_explanation()
            self.assertIn('амжилтгүй', explanation.result_text.get('1.0','end'))
            incident = app.show_timeline()
            self.assertIn('Port scan →', incident.result_text.get('1.0','end'))
            reputation = app.show_reputation()
            api.assert_not_called()
            reputation.lookup_button.invoke()
            deadline = time.monotonic()+2
            while str(reputation.lookup_button.cget('state')) == 'disabled' and time.monotonic()<deadline:
                self.root.update()
                time.sleep(0.01)
            self.assertIn('not_applicable', reputation.result_text.get('1.0','end'))
            api.assert_not_called()
            for window in [explanation, incident, reputation]:
                window.destroy()

    def test_tools_simulation_network_filter_and_reset(self):
        app = self.app
        app.simulate_tools()
        while app.session:
            if app.timer is not None:
                self.root.after_cancel(app.timer)
                app.timer = None
            app.tick()
        self.assertEqual(len(app.rows), 5)
        self.assertIn('Simulation PASS', app.stage.get())
        app.network_filters = validate_filters(src_ip='192.0.2.2', port='1000-1010', source='tshark')
        app.refresh()
        self.assertEqual(len(app.rows), 1)
        self.assertEqual(next(iter(app.rows.values()))['src_ip'], '192.0.2.2')
        app.reset_filters()
        self.assertEqual(len(app.rows), 5)

    def test_controls_remain_accessible_in_small_window(self):
        app = self.app
        for scaling in [1.0, 2.0]:
            self.root.tk.call('tk', 'scaling', scaling)
            self.root.geometry('800x600')
            self.root.update()
            for widget in [app.start_button, app.stop_button, app.demo_button,
                           app.simulation_button, app.fifty_button, app.follow_button, app.wifi_button]:
                self.assertTrue(widget.winfo_ismapped())
                right = widget.winfo_rootx() - self.root.winfo_rootx() + widget.winfo_width()
                self.assertLessEqual(right, self.root.winfo_width())
            for label in app.wrapped_labels:
                self.assertLessEqual(int(label.cget('wraplength')), 760)

    def test_wifi_access_denied_is_visible_and_stop_remains_responsive(self):
        app = self.app
        with patch('sentinelai.wifi.collect_snapshot', side_effect=PermissionError('Access denied')):
            app.start_wifi()
            deadline = time.monotonic() + 2
            while app.session.error is None and time.monotonic() < deadline:
                if app.timer is not None:
                    self.root.after_cancel(app.timer)
                    app.timer = None
                app.tick()
                self.root.update()
                time.sleep(0.01)
            self.assertIn('UNAVAILABLE', app.mode.get())
            self.assertIn('No safety assessment', app.stage.get())
            self.assertEqual(app.metrics['ALERTS'].get(), '0')
            start = time.monotonic()
            app.stop()
            self.assertLess(time.monotonic() - start, 0.5)

    def test_wifi_alert_shows_actionable_advice_without_dumping_baseline(self):
        value = dict(timestamp='2026-10-20T12:00:00+00:00', warnings=[], public_firewall_enabled=True,
            networks=[dict(interface_id='test', interface='Wi-Fi', ssid='Test hotspot', bssid='00:11:22:33:44:55',
                signal=90, security_enabled=False, auth='Open', cipher='None', ip='192.0.2.20',
                gateway='192.0.2.1', dns=['192.0.2.53'], category='Public')])
        app = self.app
        app.db.set(str(app.data_dir / 'wifi.db'))
        app.session = WifiSession(app.db.get(), lambda: value, background=False)
        app.active_db = app.db.get()
        app.follow.set(False)
        app.tick()
        self.assertEqual(len(app.rows), 1)
        app.table.selection_set('1')
        app.select()
        self.assertIn('Use HTTPS', app.details.get())
        self.assertNotIn('previous', app.details.get())
        self.assertLess(len(app.details.get()), 400)
