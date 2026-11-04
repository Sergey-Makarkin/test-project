"""Offline tests. Run: python3 -m unittest -v test_m365_smtp_evidence"""
import builtins
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import m365_direct_send_evidence as mod


class FakeSocket:
    def getpeername(self):
        return ('52.101.162.1', 25)

    def getsockname(self):
        return ('10.198.149.88', 45933)


class FakeSMTP:
    instances = []
    mode = 'success'

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.sock = FakeSocket()
        self.mail_called = False
        self.rcpt_called = False
        self.data_called = False
        self.ehlo_count = 0
        self.closed = False
        FakeSMTP.instances.append(self)

    def connect(self, mx, port):
        return (220, b'Microsoft SMTP ready')

    def ehlo(self):
        self.ehlo_count += 1
        if self.mode == 'timeout':
            raise TimeoutError('timed out')
        return (250, b'JN1PEPF... Hello [196.251.241.201]\nSTARTTLS\nPIPELINING')

    def has_extn(self, ext):
        return True

    def starttls(self, **kwargs):
        return (220, b'Ready to start TLS')

    def mail(self, sender):
        self.mail_called = True
        return (250, b'2.1.0 Sender OK')

    def rcpt(self, to):
        self.rcpt_called = True
        return (250, b'2.1.5 Recipient OK')

    def data(self, payload):
        self.data_called = True
        if self.mode == 'data_reject':
            import smtplib
            raise smtplib.SMTPDataError(554, b'5.7.1 Remote rejected')
        return (250, b'2.6.0 Queued by remote EOP')

    def close(self):
        self.closed = True


class Tests(unittest.TestCase):
    def run_case(self, mode, opts=None):
        FakeSMTP.mode = mode
        FakeSMTP.instances = []
        opts = opts or []
        with tempfile.TemporaryDirectory() as d:
            argv = ['m365_direct_send_evidence.py', '--mx','example-com.mail.protection.outlook.com',
                    '--sender','mportal@example.com','--recipient','staff@example.com',
                    '--ehlo','ml2zbx01.example.com', '--report-dir', d, '--public-ip','196.251.241.201', *opts]
            with patch('sys.argv', argv), patch('builtins.input', return_value='YES'), \
                 patch('m365_direct_send_evidence.smtplib.SMTP', FakeSMTP), \
                 patch('m365_direct_send_evidence.socket.getaddrinfo', return_value=[(2, 1, 6, '', ('52.101.162.1', 25))]), \
                 contextlib.redirect_stdout(io.StringIO()):
                exit_code = mod.main()
            jsons = list(Path(d).glob('*.json'))
            txts = list(Path(d).glob('*.txt'))
            self.assertEqual(len(jsons), 1)
            self.assertEqual(len(txts), 1)
            r = json.loads(jsons[0].read_text())
            self.assertEqual(os.stat(jsons[0]).st_mode & 0o777, 0o600)
            self.assertIn('Final SMTP submission status:', txts[0].read_text())
            return exit_code, r, FakeSMTP.instances[-1]

    def test_accepted_status_and_message_id(self):
        rc, r, client = self.run_case('success', ['--no-starttls'])
        self.assertEqual(rc, 0)
        self.assertTrue(client.data_called)
        self.assertEqual(r['public_source_ip_observed_by_m365'], '196.251.241.201')
        self.assertEqual(r['remote_ip'], '52.101.162.1')
        self.assertEqual(r['final_smtp_submission_status'], 'ACCEPTED_BY_REMOTE_SMTP_DELIVERY_NOT_CONFIRMED')
        self.assertEqual(r['local_queue_status'], 'N/A: direct client, no local queue')
        self.assertTrue(r['message_id'])

    def test_ehlo_timeout_no_message_sent(self):
        rc, r, client = self.run_case('timeout')
        self.assertEqual(rc, 1)
        self.assertFalse(client.mail_called)
        self.assertFalse(client.data_called)
        self.assertEqual(r['final_smtp_submission_status'], 'FAILED_BEFORE_DATA_NO_MESSAGE_SUBMITTED')
        self.assertTrue(any(x['stage'] == 'ERROR at EHLO' for x in r['smtp_transcript']))

    def test_tls_is_used(self):
        rc, r, client = self.run_case('success')
        self.assertEqual(rc, 0)
        self.assertTrue(r['tls_established'])
        self.assertEqual(client.ehlo_count, 2)

    def test_smtp_data_error_logged(self):
        rc, r, client = self.run_case('data_reject')
        self.assertEqual(rc, 1)
        self.assertTrue(client.data_called)
        self.assertEqual(r['final_smtp_submission_status'], 'DATA_REJECTED_BY_REMOTE_SMTP')
        self.assertIn('554', r['last_smtp_response'])

    def test_parse_public_ip(self):
        self.assertEqual(mod.observed_ip_from_ehlo(b'server Hello [196.251.241.201]\nSIZE 10000'), '196.251.241.201')
        self.assertIsNone(mod.observed_ip_from_ehlo(b'SIZE 10000'))


if __name__ == '__main__':
    unittest.main()
