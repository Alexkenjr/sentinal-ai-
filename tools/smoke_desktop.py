"""Exercise real Tk widgets with a hidden window; requires Tcl/Tk and a display."""
import sys
import tempfile
import tkinter as tk
from pathlib import Path
root_path = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root_path))
from sentinelai.gui import Application

with tempfile.TemporaryDirectory(dir=root_path) as directory:
    root = tk.Tk()
    root.withdraw()
    app = Application(root, directory)
    try:
        app.demo()
        root.update_idletasks()
        assert len(app.rows) == 3, app.status.get()
        assert app.session is None
        app.table.selection_set('1')
        app.triage('acknowledged')
        assert app.rows['1']['status'] == 'acknowledged'
        app.status_filter.set('acknowledged')
        app.refresh()
        assert list(app.rows) == ['1']
        app.status_filter.set('all')
        app.follow.set(True)
        app.start()
        assert app.session is not None
        assert app.timer is not None
        app.stop()
        assert app.timer is None
        assert app.session is None
        print('Desktop smoke: demo=3 alerts, acknowledge/filter=OK, start/stop=OK')
        app.simulate()
        while app.session:
            if app.timer is not None:
                root.after_cancel(app.timer)
                app.timer = None
            app.tick()
        assert len(app.rows) == 3
        assert 'Simulation PASS' in app.stage.get(), app.stage.get()
        app.simulate()
        app.stop()
        assert app.timer is None and app.simulation is None
        assert 'stopped early' in app.stage.get()
        print('Desktop live simulation: 19 incremental events, 3 alerts, completion and early stop=OK')
        app.simulate(50)
        while app.session:
            if app.timer is not None:
                root.after_cancel(app.timer)
                app.timer = None
            app.tick()
        assert len(app.rows) == 15
        assert '50 IPs' in app.stage.get() and 'Simulation PASS' in app.stage.get()
        print('Desktop 50-IP simulation: 120 events, 15 expected alerts=OK')
    finally:
        app.close()
