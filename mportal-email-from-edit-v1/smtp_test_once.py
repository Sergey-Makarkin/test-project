#!/usr/bin/env python3
"""One explicitly requested test email using SMTP settings saved in MPortal Admin.

Safe default prints only. --send transmits exactly one TEST message, no Zabbix writes,
no changes to the LIVE queue/database. Only an address configured for the host is allowed.
"""
import argparse
from email.message import EmailMessage
from email.utils import make_msgid
import alert_settings
import mportal_mail_live


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--host-id', required=True)
    p.add_argument('--host-name', default='')
    p.add_argument('--portal-db', default='/var/lib/maintenance-portal/audit_demo.sqlite3')
    p.add_argument('--to', help='Select one configured recipient when multiple exist')
    p.add_argument('--send', action='store_true', help='Actually submit ONE TEST message to SMTP')
    a = p.parse_args()
    cfg = alert_settings.smtp_config(a.portal_db)
    rule = alert_settings.effective_for_host(a.portal_db, a.host_id)
    recipients = rule['recipients']
    if not recipients:
        p.error('No recipients configured for this host in Administration > Email Alerting')
    if a.to:
        candidates = {x.casefold(): x for x in recipients}
        if a.to.casefold() not in candidates:
            p.error('--to must be one of the addresses configured for this host')
        recipient = candidates[a.to.casefold()]
    elif len(recipients) == 1:
        recipient = recipients[0]
    else:
        p.error('Multiple recipients configured. Specify --to to send to exactly one.')

    host = a.host_name or a.host_id
    sender = cfg['from']
    msg = EmailMessage()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = f'[MPortal][TEST ONLY] Windows {host}: SMTP configuration check'
    msg['Message-ID'] = make_msgid(domain=sender.rsplit('@', 1)[1])
    msg.set_content('\n'.join([
        'TEST ONLY. This is not a real Zabbix problem.',
        '',
        f'Host: {host} (Zabbix hostid: {a.host_id})',
        f'Route: {rule["scope"].upper()}',
        f'Project: {rule.get("project_name") or "GENERAL"}',
        f'From: {sender}',
        'No Windows service was stopped or changed.',
        'No Zabbix event was created.',
        'This message does not modify the LIVE aggregator state.',
    ]))
    print('SMTP:', cfg['host'], cfg['port'])
    print('FROM:', sender)
    print('TO:', recipient)
    print('SUBJECT:', msg['Subject'])
    if not a.send:
        print('PREVIEW ONLY: no SMTP connection made. Add --send for ONE real test email.')
        return
    mportal_mail_live.submit_one(cfg['host'], cfg['port'], sender, recipient, msg)
    print('SMTP ACCEPTED: one TEST message submitted to relay. Check real mailbox delivery.')

if __name__ == '__main__':
    main()
