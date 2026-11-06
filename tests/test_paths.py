import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from sentinelai.paths import data_directory

ROOT = Path(__file__).resolve().parents[1]


class DataPathTests(unittest.TestCase):
    def test_absolute_override_is_independent_of_cwd(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            with patch.dict(os.environ, {'SENTINELAI_DATA_DIR': directory}):
                with patch.object(Path, 'cwd', side_effect=AssertionError('Must not use cwd')):
                    self.assertEqual(data_directory(), Path(directory))

    def test_relative_override_is_rejected(self):
        with patch.dict(os.environ, {'SENTINELAI_DATA_DIR': 'relative-folder'}):
            with self.assertRaises(ValueError):
                data_directory()

    @unittest.skipUnless(os.name == 'nt', 'Windows launch regression')
    def test_gui_functions_from_system32_use_user_data(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            env = dict(os.environ, LOCALAPPDATA=directory)
            env.pop('SENTINELAI_DATA_DIR', None)
            script = '''
import sys, tkinter as tk
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
from sentinelai.gui import Application
root = tk.Tk()
root.withdraw()
app = Application(root)
try:
    assert app.data_dir == Path(sys.argv[2]) / 'SentinelAI', app.data_dir
    with patch('sentinelai.gui.messagebox.showerror', side_effect=AssertionError):
        app.demo()
        assert len(app.rows) == 3
        app.follow.set(True)
        app.start()
        assert app.session is not None
        app.stop()
        app.simulate(50)
        while app.session:
            if app.timer is not None:
                root.after_cancel(app.timer)
                app.timer = None
            app.tick()
        assert len(app.rows) == 15 and 'Simulation PASS' in app.stage.get()
        app.table.selection_set('1')
        app.triage('acknowledged')
        assert app.rows['1']['status'] == 'acknowledged'
        target = app.data_dir / 'export.csv'
        with patch('sentinelai.gui.filedialog.asksaveasfilename', return_value=str(target)):
            app.export()
        assert target.is_file()
        print('System32 launch: snapshot, monitoring, 50-IP simulation, review and export PASS')
finally:
    app.close()
'''
            result = subprocess.run([sys.executable, '-c', script, str(ROOT), directory],
                                    cwd=Path(os.environ['SystemRoot']) / 'System32', env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('export PASS', result.stdout)

    @unittest.skipUnless(os.name == 'nt', 'Windows user profile layout')
    def test_windows_default_uses_local_appdata(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            with patch.dict(os.environ, {'LOCALAPPDATA': directory, 'SENTINELAI_DATA_DIR': ''}):
                self.assertEqual(data_directory(), Path(directory) / 'SentinelAI')
