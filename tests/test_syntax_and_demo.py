"""Synthetic regression cases; fixture source is inspected, never executed."""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import airlock


class SyntaxChecks(unittest.TestCase):
    def test_rule_descriptions_and_fixture_strings_are_not_calls(self):
        source = 'description = "eval(value) and app.run(host=\'0.0.0.0\', debug=True)"\n'
        self.assertEqual(list(airlock.python_code_checks('test.py', source)), [])
        fixture = 'BAD = """try:\n    run()\nexcept Exception:\n    return \'Green\'\n"""'
        self.assertEqual(list(airlock.file_checks('test.py', fixture.splitlines())), [])

    def test_multiline_real_calls_remain_blocked(self):
        source = "app.run(\n host='0.0.0.0',\n debug=True\n)\neval(payload)\n"
        rules = {hit[0] for hit in airlock.python_code_checks('agent.py', source)}
        self.assertEqual(rules, {'open-server-bind', 'flask-debug', 'eval-exec'})

    def test_medium_rules_still_inspect_real_calls(self):
        source = "subprocess.run(command, shell=True)\nrequests.get(url, verify=False)\nyaml.load(text)\n"
        self.assertEqual({h[0] for h in airlock.python_code_checks('agent.py', source)},
                         {'shell-true', 'tls-verify-off', 'yaml-unsafe'})

    def test_literal_secret_is_still_scanned(self):
        key = 'sk-' + 'ant-' + 'Qw8Rt2Yu6Io9Pa4Sd7Fg3Hj5Kl1Zx0Cv' * 2
        self.assertTrue(airlock.find_secrets('FIXTURE = "' + key + '"'))

    def test_invalid_python_is_not_assessed(self):
        with self.assertRaises(airlock.ScanError):
            list(airlock.python_code_checks('agent.py', 'def broken('))

    def test_nested_handler_does_not_pass(self):
        source = 'def rate():\n try:\n  work()\n except Exception:\n  return "Green"\n'
        self.assertEqual([h[0] for h in airlock.file_checks('agent.py', source.splitlines())], ['fail-open-verdict'])


class SafeDemo(unittest.TestCase):
    def test_existing_demo_directory_is_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = pathlib.Path(directory) / 'keep.txt'
            marker.write_text('existing user work')
            result = subprocess.run([sys.executable, str(pathlib.Path(airlock.__file__).with_name('demo.py')),
                                     '--auto', '--directory', directory], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(marker.read_text(), 'existing user work')

    def test_synthetic_demo_checks_four_blocks_and_fixes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / 'new-demo'
            result = subprocess.run([sys.executable, str(pathlib.Path(airlock.__file__).with_name('demo.py')),
                                     '--auto', '--directory', str(target)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('Four synthetic mistakes blocked', result.stdout)
            count = subprocess.check_output(['git', '-C', str(target), 'rev-list', '--count', 'HEAD'], text=True)
            self.assertEqual(count.strip(), '5')
