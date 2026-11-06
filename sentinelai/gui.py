"""Local Tk desktop interface. All detection uses the shared MonitorSession."""
import json
import os
import sqlite3
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from datetime import datetime, timezone, timedelta
from . import __version__
from .core import Store
from .demo import generate
from .service import MonitorSession, export_alerts
from .simulation import Simulation, fresh_directory
from .theme import apply_theme
from .paths import data_directory
from .wifi import WifiSession
from .classification import TYPES
from .filters import validate as validate_filters
from .importers import convert, inventory_rows, export_inventory


class Application:
    def __init__(self, root, data_dir=None):
        self.root = root
        self.root.title(f'SentinelAI {__version__} — Local security monitor')
        width = min(1120, max(800, self.root.winfo_screenwidth() - 80))
        height = min(760, max(600, self.root.winfo_screenheight() - 100))
        self.root.geometry(f'{width}x{height}')
        self.root.minsize(800, 600)
        self.data_dir = Path(data_dir) if data_dir is not None else data_directory()
        self.session = None
        self.simulation = None
        self.timer = None
        self.rows = {}
        self.active_db = None
        self.displayed_db = None
        self.view_filter = None
        self.wrapped_labels = []
        self.path = tk.StringVar()
        self.db = tk.StringVar(value=str(self.data_dir / 'alerts.sqlite3'))
        self.config = tk.StringVar()
        self.follow = tk.BooleanVar(value=True)
        self.severity = tk.StringVar(value='all')
        self.status_filter = tk.StringVar(value='all')
        self.attack_filter = tk.StringVar(value='All types')
        self.attack_options = {'All types': None, **{value[0]: key for key, value in TYPES.items()}}
        self.network_filters = validate_filters()
        self.filter_summary = tk.StringVar(value='IP / PORT FILTERS: OFF  •  Filters menu → IP / ports')
        self.status = tk.StringVar(value='Ready — choose a JSONL log or try the synthetic demo.')
        self.details = tk.StringVar(value='Select an alert to inspect its evidence.')
        self.style = apply_theme(root)
        menubar = tk.Menu(root, background='#101c2e', foreground='#e2edf9', activebackground='#25455e', activeforeground='#ffffff')
        filters_menu = tk.Menu(menubar, tearoff=False, background='#101c2e', foreground='#e2edf9')
        filters_menu.add_command(label='IP / ports / protocol…', command=self.network_filter_dialog)
        filters_menu.add_command(label='Reset all filters', command=self.reset_filters)
        menubar.add_cascade(label='Filters', menu=filters_menu)
        tools_menu = tk.Menu(menubar, tearoff=False, background='#101c2e', foreground='#e2edf9')
        tools_menu.add_command(label='Nmap + Wireshark simulation', command=self.simulate_tools)
        tools_menu.add_command(label='Suricata + auth incident demo', command=self.simulate_investigation)
        tools_menu.add_separator()
        tools_menu.add_command(label='Import Nmap XML inventory…', command=lambda: self.import_tool('nmap'))
        tools_menu.add_command(label='Import Wireshark / TShark CSV…', command=lambda: self.import_tool('tshark'))
        tools_menu.add_command(label='Import Zeek JSON conn.log…', command=lambda: self.import_tool('zeek'))
        tools_menu.add_command(label='Import Suricata eve.json…', command=lambda: self.import_tool('suricata'))
        menubar.add_cascade(label='Tools', menu=tools_menu)
        menubar.add_command(label='AI BOT / Туслах', command=self.show_bot)
        root.configure(menu=menubar)
        self.mode = tk.StringVar(value='● IDLE')
        self.event_caption = tk.StringVar(value='EVENTS')
        self.metrics = {name: tk.StringVar(value='0') for name in ['EVENTS', 'ALERTS', 'CRITICAL']}
        frame = ttk.Frame(root, padding=20)
        frame.pack(fill='both', expand=True)
        header = ttk.Frame(frame)
        header.pack(fill='x', pady=(0, 10))
        identity = ttk.Frame(header)
        identity.pack(side='left')
        ttk.Label(identity, text='SENTINEL / AI', style='Title.TLabel').pack(anchor='w')
        ttk.Label(identity, text='SECURITY OPERATIONS  /  LOCAL NODE', style='Eyebrow.TLabel').pack(anchor='w')
        ttk.Label(header, textvariable=self.mode, style='Badge.TLabel').pack(side='right', padx=(10, 0))
        for name in reversed(list(self.metrics)):
            card = ttk.Frame(header, style='Panel.TFrame', padding=(12, 6))
            card.pack(side='right', padx=(6, 0))
            metric_style = 'Critical.Metric.TLabel' if name == 'CRITICAL' else 'Metric.TLabel'
            ttk.Label(card, textvariable=self.metrics[name], style=metric_style).pack(anchor='w')
            caption = name if name == 'EVENTS' else 'VISIBLE ' + name
            if name == 'EVENTS':
                ttk.Label(card, textvariable=self.event_caption, style='MetricCaption.TLabel').pack(anchor='w')
            else:
                ttk.Label(card, text=caption, style='MetricCaption.TLabel').pack(anchor='w')
        ttk.Separator(frame).pack(fill='x', pady=(0, 10))
        inputs = ttk.Frame(frame)
        inputs.pack(fill='x')
        inputs.columnconfigure(1, weight=1)
        self.inputs = []
        for row, (label, variable, mode) in enumerate([
                ('JSONL log', self.path, 'log'), ('Alert database', self.db, 'db'),
                ('Rules config (optional)', self.config, 'config')]):
            ttk.Label(inputs, text=label, style='Muted.TLabel').grid(row=row, column=0, sticky='w', padx=(0, 12), pady=4)
            entry = ttk.Entry(inputs, textvariable=variable)
            entry.grid(row=row, column=1, sticky='ew', pady=4)
            button = ttk.Button(inputs, text='Browse…', command=lambda v=variable, m=mode: self.browse(v, m))
            button.grid(row=row, column=2, padx=(8, 0))
            self.inputs.extend([entry, button])
        controls = ttk.Frame(frame)
        controls.pack(fill='x', pady=12)
        self.start_button = ttk.Button(controls, text='Start monitoring', command=self.start, style='Primary.TButton')
        self.start_button.grid(row=0, column=0, sticky='w', padx=(0, 6))
        self.stop_button = ttk.Button(controls, text='Stop', command=self.stop, state='disabled')
        self.stop_button.grid(row=0, column=1, sticky='w', padx=6)
        self.demo_button = ttk.Button(controls, text='Try synthetic demo', command=self.demo)
        self.demo_button.grid(row=1, column=0, sticky='w', padx=(0, 6), pady=(6, 0))
        self.simulation_button = ttk.Button(controls, text='Live simulation', command=self.simulate)
        self.simulation_button.grid(row=1, column=1, sticky='w', padx=6, pady=(6, 0))
        self.fifty_button = ttk.Button(controls, text='50-IP demo', command=lambda: self.simulate(50), style='Simulation.TButton')
        self.fifty_button.grid(row=1, column=2, sticky='w', padx=6, pady=(6, 0))
        self.wifi_button = ttk.Button(controls, text='Public Wi-Fi', command=self.start_wifi, style='Simulation.TButton')
        self.wifi_button.grid(row=1, column=3, sticky='w', padx=6, pady=(6, 0))
        ttk.Button(controls, text='Wi-Fi permissions', command=self.wifi_permissions).grid(row=0, column=3, sticky='w', padx=6)
        self.follow_button = ttk.Checkbutton(controls, text='Follow new records', variable=self.follow)
        self.follow_button.grid(row=0, column=2, sticky='w', padx=6)
        self.inputs.append(self.follow_button)
        status_label = ttk.Label(frame, textvariable=self.status, wraplength=1000, style='Muted.TLabel')
        status_label.pack(anchor='w', pady=(0, 6))
        self.wrapped_labels.append(status_label)
        self.stage = tk.StringVar(value='Live simulation: normal traffic → SSH failures → suspicious login → port scan.')
        stage_label = ttk.Label(frame, textvariable=self.stage, wraplength=1000, style='Eyebrow.TLabel')
        stage_label.pack(anchor='w', pady=(0, 6))
        self.wrapped_labels.append(stage_label)
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill='x', pady=(0, 8))
        for index, (label, variable, values) in enumerate([
                ('Severity', self.severity, ['all', 'medium', 'high', 'critical']),
                ('Status', self.status_filter, ['all', 'new', 'acknowledged', 'dismissed'])]):
            ttk.Label(toolbar, text=label).grid(row=0, column=index * 2, sticky='w')
            combo = ttk.Combobox(toolbar, textvariable=variable, values=values, state='readonly', width=15)
            combo.grid(row=0, column=index * 2 + 1, padx=6)
            combo.bind('<<ComboboxSelected>>', lambda _: self.safe_refresh())
        ttk.Label(toolbar, text='Attack / risk').grid(row=1, column=0, sticky='w', pady=(6, 0))
        self.attack_combo = ttk.Combobox(toolbar, textvariable=self.attack_filter,
            values=list(self.attack_options), state='readonly', width=20)
        self.attack_combo.grid(row=1, column=1, padx=6, pady=(6, 0))
        self.attack_combo.bind('<<ComboboxSelected>>', lambda _: self.safe_refresh())
        ttk.Button(toolbar, text='Load / refresh', command=self.safe_refresh).grid(row=1, column=2, sticky='w', pady=(6, 0))
        ttk.Button(toolbar, text='Export visible alerts…', command=self.export).grid(row=1, column=3, sticky='e', pady=(6, 0))
        ttk.Label(toolbar, textvariable=self.filter_summary, style='Muted.TLabel').grid(row=2, column=0, columnspan=4, sticky='w', pady=(4, 0))
        table_frame = ttk.Frame(frame)
        table_frame.pack(fill='both', expand=True)
        columns = ['id', 'timestamp', 'severity', 'score', 'attack_label', 'rule', 'src_ip', 'ports', 'status']
        self.table = ttk.Treeview(table_frame, columns=columns, show='headings', selectmode='browse')
        for name, width in zip(columns, [45, 195, 85, 55, 160, 175, 130, 150, 115]):
            self.table.heading(name, text='ATTACK / RISK' if name == 'attack_label' else name.replace('_', ' ').upper())
            self.table.column(name, width=width, minwidth=40, stretch=name in ('timestamp', 'rule', 'src_ip'))
        scroll = ttk.Scrollbar(table_frame, orient='vertical', command=self.table.yview)
        horizontal = ttk.Scrollbar(table_frame, orient='horizontal', command=self.table.xview)
        self.table.configure(yscrollcommand=scroll.set, xscrollcommand=horizontal.set)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        self.table.grid(row=0, column=0, sticky='nsew')
        scroll.grid(row=0, column=1, sticky='ns')
        horizontal.grid(row=1, column=0, sticky='ew')
        for severity, background, foreground in [
                ('medium', '#172637', '#f6cd76'), ('high', '#30251e', '#ffb277'),
                ('critical', '#301e32', '#ff91b7')]:
            self.table.tag_configure(severity, background=background, foreground=foreground)
        self.table.bind('<<TreeviewSelect>>', self.select)
        detail_label = ttk.Label(frame, textvariable=self.details, wraplength=1000, style='Muted.TLabel')
        detail_label.pack(anchor='w', pady=6)
        self.wrapped_labels.append(detail_label)
        actions = ttk.Frame(frame)
        actions.pack(fill='x')
        for label, status in [('Acknowledge', 'acknowledged'), ('Dismiss', 'dismissed'), ('Mark new', 'new')]:
            ttk.Button(actions, text=label, command=lambda s=status: self.triage(s)).pack(side='left', padx=(0, 6))
        investigate = ttk.Menubutton(actions, text='Investigate / Шинжлэх')
        investigate_menu = tk.Menu(investigate, tearoff=False, background='#101c2e', foreground='#e2edf9')
        investigate_menu.add_command(label='Яагаад? Offline explanation (MN)', command=self.show_explanation)
        investigate_menu.add_command(label='Incident timeline', command=self.show_timeline)
        investigate_menu.add_command(label='IP reputation — AbuseIPDB / VirusTotal', command=self.show_reputation)
        investigate.configure(menu=investigate_menu)
        investigate.pack(side='left', padx=6)
        footer = ttk.Label(frame, text='Latest 1,000 matching alerts. Scores are review priorities, not probabilities.\nWi-Fi mode observes this device only. Demo events are synthetic. Real-world accuracy is unmeasured.', wraplength=1000, style='Muted.TLabel')
        footer.pack(anchor='w', pady=(6, 0))
        self.wrapped_labels.append(footer)
        frame.bind('<Configure>', lambda event: self.resize_text(event.width))
        root.protocol('WM_DELETE_WINDOW', self.close)

    def resize_text(self, width):
        for label in self.wrapped_labels:
            label.configure(wraplength=max(200, width - 40))

    def clear_network_filters(self):
        self.network_filters = validate_filters()
        self.filter_summary.set('IP / PORT FILTERS: OFF  •  Filters menu → IP / ports')

    def reset_filters(self):
        self.clear_network_filters()
        self.severity.set('all')
        self.status_filter.set('all')
        self.attack_filter.set('All types')
        if Path(self.db.get()).is_file():
            self.safe_refresh()

    def network_filter_dialog(self):
        window = tk.Toplevel(self.root)
        window.title('IP / port filters')
        window.configure(background='#080e1a')
        window.transient(self.root)
        panel = ttk.Frame(window, padding=20)
        panel.pack(fill='both', expand=True)
        variables = {}
        fields = [('src_ip', 'Source IP / CIDR'), ('dst_ip', 'Destination IP / CIDR'),
                  ('port', 'Destination port(s)'), ('protocol', 'Protocol'), ('source', 'Telemetry source')]
        for index, (key, label) in enumerate(fields):
            ttk.Label(panel, text=label).grid(row=index, column=0, sticky='w', padx=(0, 12), pady=6)
            variable = tk.StringVar(value=self.network_filters.get(key) or '')
            variables[key] = variable
            if key in ('protocol', 'source'):
                values = ['', 'tcp', 'udp'] if key == 'protocol' else ['', 'jsonl', 'tshark', 'zeek', 'suricata', 'windows_wifi']
                entry = ttk.Combobox(panel, textvariable=variable, values=values, state='readonly', width=28)
            else:
                entry = ttk.Entry(panel, textvariable=variable, width=30)
            entry.grid(row=index, column=1, sticky='ew', pady=6)
        ttk.Label(panel, text='Examples: 192.0.2.10 or 192.0.2.0/24\nPorts: 22,80,443 or 1000-1010. Empty means any.\nUnknown destination/port evidence does not match a specific filter.',
                  style='Muted.TLabel').grid(row=5, column=0, columnspan=2, sticky='w', pady=10)
        def apply():
            try:
                selected = validate_filters(**{key: variable.get().strip() for key, variable in variables.items()})
                self.network_filters = selected
                count = sum(bool(value) for value in selected.values())
                self.filter_summary.set(f'IP / PORT FILTERS: {count} ACTIVE  •  Filters menu → IP / ports')
                if Path(self.db.get()).is_file():
                    self.refresh()
                window.destroy()
            except (ValueError, OSError, sqlite3.Error) as exc:
                messagebox.showerror('Invalid filter', str(exc), parent=window)
        ttk.Button(panel, text='Apply filters', command=apply, style='Primary.TButton').grid(row=6, column=1, sticky='e')
        ttk.Button(panel, text='Clear fields', command=lambda: [v.set('') for v in variables.values()]).grid(row=6, column=0, sticky='w')

    def simulate_tools(self):
        self.stop()
        try:
            from .tool_simulation import ToolSimulation
            self.simulation = ToolSimulation(fresh_directory(self.data_dir))
            self.path.set(str(self.simulation.path))
            self.db.set(str(self.simulation.db))
            self.config.set('')
            self.reset_filters()
            self.follow.set(True)
            self.start()
        except (ValueError, OSError) as exc:
            self.stop()
            messagebox.showerror('Tool simulation failed', str(exc))

    def simulate_investigation(self):
        self.stop()
        try:
            from .investigation_demo import InvestigationSimulation
            self.simulation = InvestigationSimulation(fresh_directory(self.data_dir))
            self.path.set(str(self.simulation.path))
            self.db.set(str(self.simulation.db))
            self.config.set('')
            self.reset_filters()
            self.follow.set(True)
            self.start()
        except (ValueError, OSError) as exc:
            self.stop()
            messagebox.showerror('Investigation demo failed', str(exc))

    def import_tool(self, format, path=None):
        if not path:
            path = filedialog.askopenfilename(title=f'Import {format} file', filetypes=[('Tool exports', '*.xml *.csv *.json *.jsonl *.log'), ('All files', '*')])
        if not path:
            return
        try:
            folder = fresh_directory(self.data_dir)
            output = folder / ('inventory.json' if format == 'nmap' else 'events.jsonl')
            result = convert(path, format, output)
            if format == 'nmap':
                self.show_inventory(result, output)
            else:
                self.stop()
                self.path.set(str(output))
                self.db.set(str(folder / 'alerts.sqlite3'))
                self.config.set('')
                self.reset_filters()
                self.follow.set(False)
                self.start()
                self.stage.set(f'{format} import: {len(result["events"])} records; invalid={result["invalid"]}; skipped={result["skipped"]}. {result.get("warning", "")}')
        except (ValueError, OSError, sqlite3.Error) as exc:
            messagebox.showerror('Import failed', str(exc))

    def show_inventory(self, report, output):
        window = tk.Toplevel(self.root)
        window.title('Nmap inventory — scanned targets, not attackers')
        window.geometry('800x520')
        window.configure(background='#080e1a')
        panel = ttk.Frame(window, padding=16)
        panel.pack(fill='both', expand=True)
        ttk.Label(panel, text=f'NMAP INVENTORY  /  {report["host_count"]} hosts  /  {report["open_ports"]} open ports', style='Eyebrow.TLabel').pack(anchor='w')
        ttk.Label(panel, text='Inventory only. No attack or vulnerability is inferred from an open port.', style='Muted.TLabel').pack(anchor='w', pady=8)
        controls = ttk.Frame(panel)
        controls.pack(fill='x', pady=8)
        target, port = tk.StringVar(), tk.StringVar()
        ttk.Label(controls, text='Target IP / CIDR').pack(side='left')
        ttk.Entry(controls, textvariable=target, width=20).pack(side='left', padx=6)
        ttk.Label(controls, text='Port(s)').pack(side='left')
        ttk.Entry(controls, textvariable=port, width=18).pack(side='left', padx=6)
        table = ttk.Treeview(panel, columns=['ip', 'port', 'protocol', 'service'], show='headings')
        for key in table['columns']:
            table.heading(key, text=key.upper())
            table.column(key, width=130, minwidth=40)
        scroll = ttk.Scrollbar(panel, command=table.yview)
        table.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        table.pack(fill='both', expand=True)
        def apply():
            try:
                rows = inventory_rows(report, target.get(), port.get())
                if table.get_children():
                    table.delete(*table.get_children())
                for row in rows[:1000]:
                    table.insert('', 'end', values=[row[k] for k in table['columns']])
                window.title(f'Nmap inventory — {len(rows)} matching services (latest view limited to 1000)')
            except ValueError as exc:
                messagebox.showerror('Invalid filter', str(exc), parent=window)
        ttk.Button(controls, text='Filter', command=apply).pack(side='left', padx=6)
        def export():
            try:
                rows = inventory_rows(report, target.get(), port.get())
                path = filedialog.asksaveasfilename(parent=window, initialdir=str(Path(output).parent),
                    defaultextension='.csv', filetypes=[('CSV', '*.csv'), ('JSON', '*.json')])
                if path:
                    if Path(path).resolve() == Path(output).resolve():
                        raise ValueError('Choose a different file from the full inventory report')
                    export_inventory(rows, path)
            except (ValueError, OSError) as exc:
                messagebox.showerror('Inventory export failed', str(exc), parent=window)
        ttk.Button(controls, text='Export', command=export).pack(side='left', padx=6)
        ttk.Label(panel, text=f'Full inventory JSON: {output}', style='Muted.TLabel', wraplength=730).pack(anchor='w', pady=8)
        apply()

    def wifi_permissions(self):
        try:
            if os.name != 'nt':
                raise OSError('Live Wi-Fi collection currently supports Windows only.')
            os.startfile('ms-settings:privacy-location')
        except OSError as exc:
            messagebox.showinfo('Wi-Fi permissions', str(exc))

    def browse(self, variable, mode):
        if mode == 'db':
            path = filedialog.asksaveasfilename(initialdir=str(self.data_dir), defaultextension='.sqlite3', confirmoverwrite=False,
                                              filetypes=[('SQLite database', '*.sqlite3'), ('All files', '*')])
        else:
            path = filedialog.askopenfilename(filetypes=[('JSON / JSONL', '*.json *.jsonl'), ('All files', '*')])
        if path:
            variable.set(path)

    def start(self):
        if self.session:
            return
        try:
            self.event_caption.set('EVENTS')
            if not self.simulation:
                self.stage.set('Monitoring your log. Synthetic event generation is off.')
            if not self.path.get().strip() or not self.db.get().strip():
                raise ValueError('Choose a log and alert database first.')
            if not self.follow.get() and not Path(self.path.get()).is_file():
                raise ValueError('Log file does not exist.')
            Path(self.db.get()).parent.mkdir(parents=True, exist_ok=True)
            self.session = MonitorSession(self.path.get(), self.db.get(), self.config.get() or None)
            self.active_db = self.db.get()
            self.set_running(True)
            self.tick()
        except (ValueError, OSError, sqlite3.Error) as exc:
            self.stop()
            messagebox.showerror('Cannot start monitoring', str(exc))

    def start_wifi(self, db=None):
        self.stop()
        try:
            self.path.set('')
            self.config.set('')
            self.db.set(str(db or self.data_dir / 'wifi-alerts.sqlite3'))
            self.severity.set('all')
            self.status_filter.set('all')
            self.attack_filter.set('All types')
            self.clear_network_filters()
            self.follow.set(True)
            self.event_caption.set('SNAPSHOTS')
            self.session = WifiSession(self.db.get())
            self.active_db = self.db.get()
            self.stage.set(self.session.status_text)
            self.set_running(True)
            self.tick()
        except (ValueError, OSError, sqlite3.Error) as exc:
            self.stop()
            messagebox.showerror('Wi-Fi monitor could not start', str(exc))

    def set_running(self, running):
        self.mode.set('● WI-FI' if running and isinstance(self.session, WifiSession) else
                      '● SIMULATION' if running and self.simulation else '● LIVE' if running else '● IDLE')
        for widget in self.inputs:
            widget.configure(state='disabled' if running else 'normal')
        self.start_button.configure(state='disabled' if running else 'normal')
        self.demo_button.configure(state='disabled' if running else 'normal')
        self.simulation_button.configure(state='disabled' if running else 'normal')
        self.fifty_button.configure(state='disabled' if running else 'normal')
        self.wifi_button.configure(state='disabled' if running else 'normal')
        self.stop_button.configure(state='normal' if running else 'disabled')

    def tick(self):
        self.timer = None
        if not self.session:
            return
        try:
            if self.simulation and not self.simulation.complete:
                stage, _ = self.simulation.step()
                self.stage.set(f'SYNTHETIC • {self.simulation.position}/{len(self.simulation.plan)} • {stage}')
            _, warnings = self.session.poll()
            if isinstance(self.session, WifiSession):
                self.stage.set(self.session.status_text)
                snapshot = self.session.last_snapshot
                state = ('UNAVAILABLE' if self.session.error else 'COLLECTING' if snapshot is None else
                         'NO WI-FI' if not snapshot['networks'] else 'PARTIAL' if snapshot.get('warnings') else 'WI-FI')
                self.mode.set('● ' + state)
            self.metrics['EVENTS'].set(str(self.session.records))
            note = f' • Last warning: {warnings[-1]}' if warnings else ''
            self.status.set('Monitoring • ' + self.session.summary() + note)
            self.refresh()
            if self.simulation and self.simulation.complete:
                result = self.simulation.report(self.session.store)
                self.stage.set('Simulation ' + ('PASS' if result['passed'] else 'FAIL') +
                               f' • {result["unique_ips"]} IPs • Expected {result["expected_alert_count"]} alerts; observed {len(result["observed_rules"])}. Reports saved beside the log.')
                self.stop()
                return
            if self.follow.get():
                interval = 100 if self.simulation and self.simulation.hosts == 50 else 500
                self.timer = self.root.after(interval, self.tick)
            else:
                self.stop()
        except (ValueError, OSError, sqlite3.Error) as exc:
            self.stop()
            self.status.set(f'Monitor stopped: {exc}')

    def stop(self):
        if self.timer is not None:
            self.root.after_cancel(self.timer)
            self.timer = None
        if self.session:
            self.status.set('Stopped • ' + self.session.summary())
            self.session.close()
            self.session = None
        self.set_running(False)
        if self.simulation and not self.simulation.complete:
            self.stage.set('Simulation stopped early. Click Live simulation to start a fresh run.')
        self.simulation = None

    def simulate(self, hosts=6):
        self.stop()
        try:
            self.simulation = Simulation(fresh_directory(self.data_dir), hosts)
            self.path.set(str(self.simulation.path))
            self.db.set(str(self.simulation.db))
            self.config.set('')
            self.severity.set('all')
            self.status_filter.set('all')
            self.attack_filter.set('All types')
            self.clear_network_filters()
            self.follow.set(True)
            self.start()
        except (OSError, ValueError) as exc:
            self.stop()
            messagebox.showerror('Simulation failed', str(exc))

    def demo(self):
        self.stop()
        try:
            directory = self.data_dir / ('demo-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
            self.path.set(str(generate(directory / 'events.jsonl')))
            self.db.set(str(directory / 'alerts.sqlite3'))
            self.config.set('')
            self.severity.set('all')
            self.status_filter.set('all')
            self.attack_filter.set('All types')
            self.clear_network_filters()
            self.follow.set(False)
            self.start()
            self.stage.set('Synthetic snapshot: 14 events, 3 expected alerts.')
        except OSError as exc:
            messagebox.showerror('Demo failed', str(exc))

    def refresh(self):
        db = self.active_db if self.session else self.db.get()
        if not db or not Path(db).is_file():
            raise ValueError('Choose an existing database or run monitoring first.')
        store = self.session.store if self.session else Store(db)
        try:
            rows = store.list_alerts(None if self.severity.get() == 'all' else self.severity.get(),
                                     None if self.status_filter.get() == 'all' else self.status_filter.get(),
                                     attack_type=self.attack_options[self.attack_filter.get()], **self.network_filters)
        finally:
            if not self.session:
                store.close()
        selection = self.table.selection()
        view_filter = (self.severity.get(), self.status_filter.get(), self.attack_filter.get(), tuple(sorted(self.network_filters.items())))
        same_view = self.displayed_db == db and self.view_filter == view_filter
        old_rows = self.rows if same_view else {}
        next_rows = {str(row['id']): row for row in rows}
        if not same_view:
            children = self.table.get_children()
            if children:
                self.table.delete(*children)
        else:
            removed = set(old_rows) - set(next_rows)
            if removed:
                self.table.delete(*removed)
        self.rows = next_rows
        self.metrics['ALERTS'].set(str(len(next_rows)))
        self.metrics['CRITICAL'].set(str(sum(row['severity'] == 'critical' for row in next_rows.values())))
        self.displayed_db, self.view_filter = db, view_filter
        # Keep unchanged rows in place, preserving scroll, focus and selection.
        for index, (item_id, row) in enumerate(next_rows.items()):
            port_text = ','.join(map(str, row['evidence'].get('dst_ports', []))) or 'unknown'
            values = [port_text if k == 'ports' else row[k] for k in self.table['columns']]
            if item_id not in old_rows:
                self.table.insert('', index, iid=item_id, values=values, tags=(row['severity'],))
            elif row != old_rows[item_id]:
                self.table.item(item_id, values=values, tags=(row['severity'],))
        if not same_view:
            self.table.yview_moveto(0)
        if not selection or selection[0] not in self.rows or not same_view:
            self.details.set('Select an alert to inspect its evidence.')
        else:
            self.select()

    def safe_refresh(self):
        try:
            self.refresh()
        except (ValueError, OSError, sqlite3.Error) as exc:
            messagebox.showerror('Cannot load alerts', str(exc))

    def show_bot(self):
        from .bot import ask, evidence_context
        selection = self.table.selection()
        alert = self.rows.get(selection[0]) if selection else None
        db = self.displayed_db if alert else (self.active_db if self.session else self.db.get())
        try:
            context = evidence_context(db, alert['id'] if alert else None)
        except (OSError, ValueError, sqlite3.Error) as exc:
            messagebox.showerror('AI Bot', str(exc))
            return
        window = tk.Toplevel(self.root)
        window.title('SENTINEL / AI BOT')
        window.geometry('850x650')
        panel = ttk.Frame(window, padding=16)
        panel.pack(fill='both', expand=True)
        ttk.Label(panel, text='AI BOT / SECURITY ASSISTANT', style='Title.TLabel').pack(anchor='w')
        scope = f'Alert #{alert["id"]}' if alert else 'Сүүлийн 20 alert'
        ttk.Label(panel, text=scope + ' • Нээх үеийн snapshot • Local Ollama • Read-only', style='Muted.TLabel').pack(anchor='w')
        model = tk.StringVar(value=os.environ.get('SENTINELAI_BOT_MODEL', ''))
        ttk.Label(panel, text='Ollama model (суулгасан нэр)').pack(anchor='w', pady=(8, 0))
        ttk.Entry(panel, textvariable=model).pack(fill='x')
        text = tk.Text(panel, wrap='word', background='#0b1423', foreground='#e2edf9', font=('Segoe UI', 11))
        text.pack(fill='both', expand=True, pady=10)
        def append(value):
            text.configure(state='normal')
            text.insert('end', value + '\n\n')
            text.see('end')
            text.configure(state='disabled')
        append('SentinelAI: Асуултаа бичнэ үү. Жишээ: Яагаад энэ alert үүссэн, дараа нь юуг шалгах вэ?\nAI хариуг эх логтой тулгаж шалгана уу. Model байхгүй бол Ollama суулгаж, model татаж ажиллуулна.')
        question = tk.StringVar(value='Яагаад энэ alert үүссэн, дараа нь юуг шалгах вэ?')
        entry = ttk.Entry(panel, textvariable=question)
        entry.pack(fill='x')
        status = tk.StringVar(value='Ready — model нэр шаардлагатай')
        ttk.Label(panel, textvariable=status, style='Muted.TLabel').pack(anchor='w')
        history, replies = [], queue.Queue()
        def send():
            prompt, chosen = question.get().strip(), model.get().strip()
            if not prompt or not chosen:
                status.set('Асуулт болон model нэр оруулна уу.')
                return
            send_button.configure(state='disabled')
            append('You: ' + prompt)
            status.set('Local AI хариулж байна…')
            def worker():
                try:
                    replies.put((ask(prompt, context, list(history), chosen), None))
                except Exception as exc:
                    replies.put((None, str(exc)))
            threading.Thread(target=worker, daemon=True).start()
            def poll():
                try:
                    result, error = replies.get_nowait()
                except queue.Empty:
                    window.bot_timer = window.after(100, poll)
                    return
                if error:
                    append('Unavailable: ' + error)
                    status.set('AI unavailable — хариу үүсгээгүй')
                else:
                    append('SentinelAI: ' + result['answer'])
                    history.extend([dict(role='user', content=prompt), dict(role='assistant', content=result['answer'])])
                    status.set(result['caution'])
                    question.set('')
                send_button.configure(state='normal')
            window.bot_timer = window.after(100, poll)
        send_button = ttk.Button(panel, text='Send / Илгээх', command=send, style='Primary.TButton')
        send_button.pack(anchor='e', pady=6)
        def closed(event):
            if event.widget is window and hasattr(window, 'bot_timer'):
                window.after_cancel(window.bot_timer)
        window.bind('<Destroy>', closed)
        return window

    def selected_context(self):
        selection = self.table.selection()
        if not selection or selection[0] not in self.rows:
            messagebox.showinfo('Alert сонгоно уу', 'Эхлээд шалгах alert мөрөө сонгоно уу.')
            return None
        return self.displayed_db, self.rows[selection[0]]

    def text_report(self, title, text, data, name):
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry('900x620')
        window.configure(background='#080e1a')
        panel = ttk.Frame(window, padding=16)
        panel.pack(fill='both', expand=True)
        ttk.Label(panel, text=title, style='Eyebrow.TLabel').pack(anchor='w', pady=(0, 8))
        ttk.Label(panel, text='Нээх үеийн snapshot. Шинэ log орсны дараа дахин нээж шинэчилнэ.', style='Muted.TLabel').pack(anchor='w')
        body = ttk.Frame(panel)
        body.pack(fill='both', expand=True, pady=8)
        widget = tk.Text(body, background='#0b1423', foreground='#e2edf9', insertbackground='#52ead1',
                         font=('Segoe UI', 10), wrap='word', borderwidth=0, padx=12, pady=12)
        scroll = ttk.Scrollbar(body, command=widget.yview)
        widget.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        widget.pack(fill='both', expand=True)
        widget.insert('1.0', text)
        widget.configure(state='disabled')
        window.result_text = widget
        def export():
            path = filedialog.asksaveasfilename(parent=window, initialdir=str(self.data_dir),
                initialfile=name, defaultextension='.json', filetypes=[('JSON', '*.json')])
            if path:
                try:
                    if self.displayed_db and Path(path).resolve() == Path(self.displayed_db).resolve():
                        raise ValueError('Database дээр дарж бичихгүй.')
                    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
                except (OSError, ValueError) as exc:
                    messagebox.showerror('Export failed', str(exc), parent=window)
        ttk.Button(panel, text='Export JSON', command=export).pack(anchor='e')
        return window

    def show_explanation(self):
        context = self.selected_context()
        if not context:
            return
        db, alert = context
        store = None
        try:
            from .insights import explain, explanation_text
            store = Store(db)
            result = explain(store, alert['id'])
            return self.text_report('Яагаад энэ alert үүсэв? / Offline evidence', explanation_text(result), result, f'alert-{alert["id"]}-mn.json')
        except (ValueError, OSError, sqlite3.Error) as exc:
            messagebox.showerror('Explanation failed', str(exc))
        finally:
            if store:
                store.close()

    def show_timeline(self):
        context = self.selected_context()
        if not context:
            return
        db, alert = context
        store = None
        try:
            from .insights import timeline
            stamp = datetime.fromisoformat(alert['timestamp'])
            store = Store(db)
            result = timeline(store, alert['src_ip'], (stamp-timedelta(minutes=15)).isoformat(),
                              (stamp+timedelta(minutes=15)).isoformat())
            lines = [f'IP: {result["ip"]} | Сонгосон alert-аас ±15 минут | gap=15 минут',
                     'Ижил source/target + цагийн ойролцоо байдал нь шалтгаан эсвэл compromise нотлохгүй.',
                     f'Хүрээ хязгаарлагдсан: {result["truncated"]}\n']
            for incident in result['incidents']:
                lines.extend([f'INCIDENT {incident["incident_id"]} | target={incident["dst_ip"]}', incident['title_mn'],
                              f'{incident["start"]} → {incident["end"]}'])
                entries = []
                for event in incident['events']:
                    detail = (f"{event['event_type']} {event.get('outcome', '')} user={event.get('username', '-')} "
                              f"port={event.get('dst_port', '-')} source={event.get('source', 'jsonl')} log={event['log_id'][:16]} late={event['late']}")
                    entries.append((event['timestamp'], 0, detail))
                for item in incident['alerts']:
                    entries.append((item['timestamp'], 1, f"ALERT #{item['id']} {item['rule']} {item['severity']}"))
                lines.extend(f'{time} | {detail}' for time, _, detail in sorted(entries))
                lines.append('')
            if not result['incidents']:
                lines.append('Хадгалсан normalized event олдоогүй. Хуучин alert-аас дараалал зохиогоогүй.')
            lines.append('Холбоогүй/хуучин alert: ' + json.dumps(result['unlinked_alerts'], ensure_ascii=False))
            return self.text_report('Incident timeline / Монгол', '\n'.join(lines), result, 'incident-timeline.json')
        except (ValueError, OSError, sqlite3.Error) as exc:
            messagebox.showerror('Timeline failed', str(exc))
        finally:
            if store:
                store.close()

    def show_reputation(self):
        context = self.selected_context()
        if not context:
            return
        db, alert = context
        from .reputation import cached, lookup
        window = tk.Toplevel(self.root)
        window.title('IP reputation — эх сурвалж ба огноо')
        window.geometry('900x620')
        window.configure(background='#080e1a')
        panel = ttk.Frame(window, padding=16)
        panel.pack(fill='both', expand=True)
        ttk.Label(panel, text=f'IP REPUTATION / {alert["src_ip"]}', style='Eyebrow.TLabel').pack(anchor='w')
        ttk.Label(panel, text='Lookup дарахад public IP-г provider руу илгээнэ. Log явуулахгүй; API key нь зөвхөн provider-ийн authentication header-д орно.\nVirusTotal queried IP-г dataset-д оруулж болно. Private/local IP-г API руу явуулахгүй.',
                  wraplength=840, style='Muted.TLabel').pack(anchor='w', pady=8)
        provider = tk.StringVar(value='abuseipdb')
        combo = ttk.Combobox(panel, textvariable=provider, values=['abuseipdb','virustotal','both'], state='readonly')
        combo.pack(anchor='w')
        body = ttk.Frame(panel)
        body.pack(fill='both', expand=True, pady=8)
        text = tk.Text(body, background='#0b1423', foreground='#e2edf9', wrap='word', font=('Segoe UI', 10), padx=12, pady=12)
        scrollbar = ttk.Scrollbar(body, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        text.pack(fill='both', expand=True)
        def render(results):
            evidence = alert['evidence']
            lines = [f"Локал шалтгаан: alert #{alert['id']} / {alert['attack_label']} / rule={alert['rule']}",
                     f"Хадгалсан count={evidence.get('count', '?')}, window={evidence.get('window_seconds', '?')}s, threshold={evidence.get('threshold', 'хамаарахгүй / хадгалагдаагүй')}",
                     'Энэ IP нь илгээгчийн хаяг; халдагчийн identity гэсэн баталгаа биш.',
                     'Provider-ийн мэдээлэл alert үүссэн үеийн үнэлгээ биш; татсан цагийг тусад нь шалгана.\n']
            if evidence.get('signature'):
                lines.insert(1, f"Suricata SID={evidence.get('signature_id')} / {evidence['signature']}")
            for item in results:
                lines.extend([f"Provider: {item['provider']} | status={item['status']} | freshness={item.get('freshness', 'unknown')}",
                    item.get('reason_mn', ''), f"Provider огноо: {item.get('provider_updated_at') or 'мэдэгдэхгүй'}",
                    item.get('update_meaning', ''), f"Татсан цаг: {item.get('fetched_at') or 'таталт хийгдээгүй'}",
                    f"Эх сурвалж: {item.get('source_url', '-')}", item.get('lookup_error', ''), ''])
            if not results:
                lines.append('Cached мэдээлэл байхгүй. ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEY тохируулж, Lookup дарна. Key-г чат эсвэл source code-д бичих шаардлагагүй.')
            text.configure(state='normal')
            text.delete('1.0', 'end')
            text.insert('1.0', '\n'.join(lines))
            text.configure(state='disabled')
        store = Store(db)
        try:
            render(cached(store, alert['src_ip']))
        finally:
            store.close()
        results_queue = queue.Queue()
        timer = [None]
        def wait_result():
            timer[0] = None
            try:
                result = results_queue.get_nowait()
            except queue.Empty:
                timer[0] = window.after(100, wait_result)
                return
            render(result)
            button.configure(state='normal')
        def refresh():
            selected = ['abuseipdb','virustotal'] if provider.get() == 'both' else [provider.get()]
            button.configure(state='disabled')
            def work():
                connection = None
                try:
                    connection = Store(db)
                    result = [lookup(connection, alert['src_ip'], name, refresh=True) for name in selected]
                except Exception:
                    result = [dict(provider=name, status='unavailable', reason_mn='Lookup эсвэл cache хадгалалт амжилтгүй. Шинэчилсэн гэж үзээгүй.') for name in selected]
                finally:
                    if connection:
                        connection.close()
                results_queue.put(result)
            threading.Thread(target=work, daemon=True, name='SentinelAI-Reputation').start()
            timer[0] = window.after(100, wait_result)
        button = ttk.Button(panel, text='Lookup / refresh (send public IP)', command=refresh, style='Primary.TButton')
        button.pack(anchor='e')
        def destroy(event):
            if event.widget == window and timer[0] is not None:
                window.after_cancel(timer[0])
                timer[0] = None
        window.bind('<Destroy>', destroy, add='+')
        window.result_text, window.lookup_button, window.provider_var = text, button, provider
        return window

    def select(self, _=None):
        selection = self.table.selection()
        if selection and selection[0] in self.rows:
            row = self.rows[selection[0]]
            evidence = row['evidence']
            if evidence.get('source_kind') == 'local_device':
                self.details.set(f"#{row['id']} • {row['attack_label']} • {row['classification']} • {row['status']}\n{evidence.get('advice', '')}\n"
                    f"{evidence.get('ssid', '?')} | {evidence.get('auth', '?')}/{evidence.get('cipher', '?')} | "
                    f"Gateway: {evidence.get('gateway') or 'unknown'} | DNS: {', '.join(evidence.get('dns') or []) or 'unknown'}")
            else:
                port_values = ','.join(map(str, evidence.get('dst_ports', [])[:12])) or 'unknown'
                targets = ', '.join(evidence.get('destinations', [])[:3]) or 'unknown'
                self.details.set(f"#{row['id']} • {row['attack_label']} • {row['classification']} • {row['status']}\n"
                    f"Count {evidence.get('count', '?')} / {evidence.get('window_seconds', '?')}s | Source: {evidence.get('source', 'jsonl')} | "
                    f"Ports: {port_values} | Destinations: {targets}. Full evidence is in export.")

    def triage(self, status):
        selection = self.table.selection()
        if not selection:
            messagebox.showinfo('Select an alert', 'Select a row before changing its review status.')
            return
        store = None
        try:
            store = Store(self.displayed_db)
            store.set_status(int(selection[0]), status)
            # Do not apply visible row IDs to a newly selected database.
            current_db = self.active_db if self.session else self.db.get()
            if current_db == self.displayed_db:
                self.refresh()
            else:
                self.rows[selection[0]]['status'] = status
                self.table.set(selection[0], 'status', status)
                self.select()
        except (ValueError, OSError, sqlite3.Error) as exc:
            messagebox.showerror('Cannot update alert', str(exc))
        finally:
            if store:
                store.close()

    def export(self):
        path = filedialog.asksaveasfilename(initialdir=str(self.data_dir), defaultextension='.csv', filetypes=[('CSV', '*.csv'), ('JSON', '*.json')])
        if path:
            try:
                export_alerts(list(self.rows.values()), path)
                self.status.set(f'Exported {len(self.rows)} visible alerts to {path}')
            except OSError as exc:
                messagebox.showerror('Export failed', str(exc))

    def close(self):
        self.stop()
        self.root.destroy()


def launch(simulate=False, data_dir=None, hosts=6, wifi=False, wifi_db=None, tools=False, investigation=False):
    root = tk.Tk()
    app = Application(root, data_dir)
    if investigation:
        root.after(200, app.simulate_investigation)
    elif tools:
        root.after(200, app.simulate_tools)
    elif wifi:
        root.after(200, lambda: app.start_wifi(wifi_db))
    elif simulate:
        root.after(200, lambda: app.simulate(hosts))
    root.mainloop()
    return 0
