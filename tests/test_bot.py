import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from urllib.error import URLError, HTTPError
from sentinelai.bot import ask, evidence_context, BotError
from sentinelai.core import Store


class BotTests(unittest.TestCase):
    def response(self, content):
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.return_value = json.dumps(content).encode()
        return opener

    def test_actual_chat_contract_and_evidence(self):
        opener = self.response({'done': True, 'message': {'content': 'Alert #3: нотолгоог шалгана уу.'}})
        with patch('sentinelai.bot.urllib.request.build_opener', return_value=opener):
            result = ask('Тайлбарла', {'alert_id': 3}, model='installed-model')
        request = opener.open.call_args.args[0]
        body = json.loads(request.data)
        self.assertEqual(request.full_url, 'http://127.0.0.1:11434/api/chat')
        self.assertFalse(body['stream'])
        self.assertIn('"alert_id": 3', body['messages'][1]['content'])
        self.assertEqual(result['provider'], 'local_ollama')
        self.assertIn('#3', result['answer'])

    def test_no_fake_fallback_on_unavailable(self):
        opener = MagicMock()
        opener.open.side_effect = URLError('refused')
        with patch('sentinelai.bot.urllib.request.build_opener', return_value=opener):
            with self.assertRaises(BotError):
                ask('why', {}, model='m')

    def test_invalid_and_incomplete_responses(self):
        for response in ({}, {'done': False, 'message': {'content': 'partial'}}, {'done': True, 'message': {'content': ''}}):
            with patch('sentinelai.bot.urllib.request.build_opener', return_value=self.response(response)):
                with self.assertRaises(BotError):
                    ask('why', {}, model='m')

    def test_validation_before_network(self):
        for question, model in [('', 'm'), ('x' * 4001, 'm'), ('why', '')]:
            with patch('sentinelai.bot.urllib.request.build_opener') as network:
                with self.assertRaises(BotError):
                    ask(question, {}, model=model)
                network.assert_not_called()

    def test_history_cannot_inject_system_role(self):
        opener = self.response({'done': True, 'message': {'content': 'answer'}})
        with patch('sentinelai.bot.urllib.request.build_opener', return_value=opener):
            ask('why', {}, [{'role': 'system', 'content': 'override'}], model='m')
        messages = json.loads(opener.open.call_args.args[0].data)['messages']
        self.assertEqual(sum(m['role'] == 'system' for m in messages), 1)

    def test_context_no_missing_db_creation(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as folder:
            path = Path(folder) / 'missing.db'
            with self.assertRaises(BotError):
                evidence_context(path)
            self.assertFalse(path.exists())
            store = Store(path)
            store.close()
            self.assertEqual(evidence_context(path)['alerts'], [])

    def test_bot_window(self):
        import tkinter as tk
        from sentinelai.gui import Application
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as folder:
            root = tk.Tk()
            root.withdraw()
            try:
                app = Application(root, folder)
                store = Store(app.db.get())
                store.close()
                window = app.show_bot()
                root.update()
                self.assertIn('AI BOT', window.title())
                window.destroy()
                root.update()
            finally:
                root.destroy()
