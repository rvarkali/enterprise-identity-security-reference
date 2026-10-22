"""Validity preflight tests: no certificates or external commands are generated."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import generate


class ValidityTests(unittest.TestCase):
    def parse_validity(self, flags, expected):
        with patch('sys.argv', ['generate.py', '--uri', 'urn:iam:policy-reader',
                   '--subject', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', *flags]), \
             patch.object(generate, 'validity_days', side_effect=RuntimeError('parsed')) as validate:
            with self.assertRaisesRegex(RuntimeError, 'parsed'):
                generate.main()
            validate.assert_called_once_with(*expected)
        self.assertEqual(expected, generate.validity_days(*expected))

    def test_defaults(self):
        self.parse_validity([], (365, 90, 30))

    def test_independent_custom_values(self):
        self.parse_validity(['--ca-days', '14', '--server-days', '5', '--client-days', '2'], (14, 5, 2))
        self.parse_validity(['--client-days', '45'], (365, 90, 45))

    def test_invalid_cli_creates_no_artifacts_or_commands(self):
        cases = [('0', '2', '1'), ('7', '0', '1'), ('7', '2', '-1'),
                 ('7', '7', '1'), ('7', '2', '7'), ('7', '8', '1'),
                 ('7', '2', '8'), ('1.5', '1', '1'), ('999999999999', '2', '1')]
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'absent'
            for ca, server, client in cases:
                with self.subTest(ca=ca, server=server, client=client), \
                     patch('sys.argv', ['generate.py', '--uri', 'urn:iam:policy-reader',
                           '--subject', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '--output', str(output),
                           '--ca-days', ca, '--server-days', server, '--client-days', client]), \
                     patch.object(generate.subprocess, 'run') as run, contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        generate.main()
                    self.assertEqual(2, error.exception.code)
                    self.assertFalse(output.exists())
                    run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
