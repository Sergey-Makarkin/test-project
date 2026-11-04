#!/usr/bin/env python3
"""Independent Microsoft 365 Direct Send SMTP evidence collector.

No connection to Maintenance Portal, Zabbix, or local mail queues.
One message / one SMTP transaction. Generates local JSON and TXT incident logs.
Python 3.10+, standard library only.
"""

import argparse
import ipaddress
import json
import os
import re
import smtplib
import socket
import ssl
import sys
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from pathlib import Path


def now_pair():
    return {
        "local": datetime.now().astimezone().isoformat(timespec="milliseconds"),
        "utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
    }


def clean_answer(label, supplied=None, required=True):
    if supplied is None:
        supplied = input(f"{label}: ")
    value = supplied.strip()
    if any(ch in value for ch in "\r\n\x00"):
        raise ValueError(f"Invalid characters in {label}")
    if required and not value:
        raise ValueError(f"Required field is empty: {label}")
    return value


def format_reply(raw):
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


def observed_ip_from_ehlo(reply):
    text = format_reply(reply)
    match = re.search(r"\bHello\s+\[([^\]]+)\]", text, re.IGNORECASE)
    if not match:
        return None
    try:
        return str(ipaddress.ip_address(match.group(1)))
    except ValueError:
        return None


def add_step(report, stage, code=None, response=None, extra=None):
    event = {"stage": stage, **now_pair()}
    if code is not None:
        event["smtp_code"] = int(code)
    if response is not None:
        event["smtp_response"] = format_reply(response)
    if extra is not None:
        event["detail"] = str(extra)
    report["smtp_transcript"].append(event)
    if code is not None:
        report["last_smtp_response"] = f"{code} {format_reply(response)}"
    return event


def build_msg(sender, recipient, case_id):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = f"[MPortal][M365 SUPPORT CASE] Direct Send check {case_id}"
    msg["Date"] = format_datetime(datetime.now().astimezone())
    msg["Message-ID"] = make_msgid(idstring=f"m365-evidence-{case_id}")
    msg["X-MPortal-Diagnostic-ID"] = case_id
    msg.set_content(
        "Microsoft 365 Direct Send transport diagnostic.\n"
        f"Case ID: {case_id}\n"
        "Sent directly by a standalone Python SMTP client.\n"
        "No Zabbix alert was generated. No Windows services were stopped.\n"
    )
    return msg


def write_private(path, content):
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(str(path), flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def summarize(report):
    ip = report.get("public_source_ip_observed_by_m365")
    supplied = report.get("public_source_ip_supplied")
    chosen_ip = ip or supplied or "UNKNOWN (verify public NAT address)"
    src_info = ("observed in Microsoft 365 EHLO" if ip else
                "operator-supplied (not independently verified)" if supplied else
                "not established: no Microsoft EHLO reply")
    submitted = report['final_smtp_submission_status'] == 'ACCEPTED_BY_REMOTE_SMTP_DELIVERY_NOT_CONFIRMED'
    if submitted:
        delivery_line = "UNKNOWN from SMTP alone; verify in Exchange Message Trace"
    elif report['final_smtp_submission_status'] == 'UNKNOWN_AFTER_DATA_ERROR_MAY_HAVE_BEEN_ACCEPTED':
        delivery_line = "UNKNOWN after DATA transport error; verify in Exchange Message Trace"
    else:
        delivery_line = "NOT SUBMITTED in this SMTP transaction"
    lines = [
        "MICROSOFT 365 SMTP OUTBOUND TRANSPORT EVIDENCE",
        "===========================================",
        "Type: Direct Python -> Microsoft 365 MX (NOT a Postfix/gateway queue record)",
        f"Case ID: {report['case_id']}",
        f"Sender (MAIL FROM): {report['sender']}",
        f"Recipient (RCPT TO): {report['recipient']}",
        f"Subject: {report['subject']}",
        f"Message-ID: {report['message_id']}",
        f"Start time (local with offset): {report['started']['local']}",
        f"Start time (UTC): {report['started']['utc']}",
        f"End time (local with offset): {report['finished']['local']}",
        f"End time (UTC): {report['finished']['utc']}",
        f"Destination hostname: {report['remote_host']}",
        f"Remote destination IP: {report.get('remote_ip') or 'UNKNOWN'}",
        f"Destination port: {report['remote_port']}",
        f"Local source IP: {report.get('local_source_ip') or 'UNKNOWN'}",
        f"Local source port: {report.get('local_source_port') or 'UNKNOWN'}",
        f"Public source IP: {chosen_ip}",
        f"Public IP evidence: {src_info}",
        f"TLS established: {'yes' if report['tls_established'] else 'no'}",
        f"Authentication: none",
        f"Last SMTP response received: {report.get('last_smtp_response') or 'NONE'}",
        f"Failed at stage: {report.get('failed_stage') or 'NONE'}",
        f"Response at failed stage: {'NO REPLY (transport error)' if report.get('failed_stage') and not report.get('failed_stage_code') else report.get('failed_stage_code') or 'N/A'}",
        f"Final SMTP submission status: {report['final_smtp_submission_status']}",
        "Local queue status: NOT APPLICABLE: no Postfix or persistent local mail queue used",
        f"Final mailbox delivery status: {delivery_line}",
    ]
    if report.get("error"):
        lines.append(f"Error: {report['error']}")
    if ip and supplied and ip != supplied:
        lines.append("WARNING: Operator-supplied public IP differs from Microsoft-observed public IP!")
    lines.extend(["", "SMTP SESSION TRANSCRIPT (times include local offset and UTC):"])
    for e in report["smtp_transcript"]:
        label = f"[{e['local']} / {e['utc']}] {e['stage']}"
        if "smtp_code" in e:
            label += f": {e['smtp_code']} {e.get('smtp_response', '')}"
        if "detail" in e:
            label += f" | {e['detail']}"
        lines.append(label)
    lines.extend([
        "", "IMPORTANT:",
        "For a genuine gateway outbound relay/queue record, obtain the relay's own logs.",
        "A failed EHLO before MAIL FROM means NO MESSAGE was submitted or queued by this script.",
        "A 250 response after DATA confirms SMTP acceptance, NOT mailbox delivery.",
    ])
    return "\n".join(lines) + "\n"


def main():
    p = argparse.ArgumentParser(description="Collect complete SMTP evidence for Microsoft support (standalone)")
    p.add_argument("--mx", help="Real Microsoft 365 MX hostname")
    p.add_argument("--sender", help="Envelope MAIL FROM / From header")
    p.add_argument("--recipient", help="Envelope RCPT TO / To header")
    p.add_argument("--ehlo", help="Client EHLO FQDN")
    p.add_argument("--public-ip", help="Known outgoing NAT IP (optional; evidence source is flagged)")
    p.add_argument("--timeout", type=int, default=20, help="Per-command timeout, default 20 sec")
    p.add_argument("--no-starttls", action="store_true", help="Disable STARTTLS for troubleshooting only")
    p.add_argument("--report-dir", default="./m365-smtp-evidence", help="Local private output directory")
    args = p.parse_args()
    if not 3 <= args.timeout <= 120:
        p.error("--timeout must be 3..120")

    print("=== M365 Direct Send: support evidence ===")
    print("No portal imports. One attempt, one email at most. Reports contain actual addresses.")
    try:
        mx = clean_answer("Real Microsoft 365 MX", args.mx)
        sender = clean_answer("Sender / MAIL FROM", args.sender)
        recipient = clean_answer("Recipient / RCPT TO", args.recipient)
        ehlo = clean_answer("EHLO FQDN", args.ehlo)
        public_ip = clean_answer("Public NAT IP (Enter if unknown)", args.public_ip, required=False)
        if public_ip:
            public_ip = str(ipaddress.ip_address(public_ip))
        if not re.fullmatch(r"[^@\s]+@[^@\s]+", sender) or not re.fullmatch(r"[^@\s]+@[^@\s]+", recipient):
            raise ValueError("Invalid sender/recipient email address")
        if re.search(r"\s", mx) or re.search(r"\s", ehlo):
            raise ValueError("MX/EHLO must not contain whitespace")
        confirm = input("Send ONE real diagnostic message? Type YES: ").strip()
        if confirm != "YES":
            print("Cancelled. Nothing sent.")
            return 0
    except (ValueError, EOFError, KeyboardInterrupt) as exc:
        print(f"Invalid input/cancelled: {exc}", file=sys.stderr)
        return 2

    case_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
    msg = build_msg(sender, recipient, case_id)
    report = {
        "record_type": "direct_python_smtp_transport_not_gateway_queue",
        "case_id": case_id,
        "started": now_pair(),
        "sender": sender,
        "recipient": recipient,
        "subject": msg["Subject"],
        "message_id": msg["Message-ID"],
        "ehlo_hostname": ehlo,
        "remote_host": mx,
        "remote_port": 25,
        "public_source_ip_supplied": public_ip or None,
        "public_source_ip_observed_by_m365": None,
        "local_source_ip": None,
        "local_source_port": None,
        "remote_ip": None,
        "tls_established": False,
        "authentication": "none",
        "local_queue_status": "N/A: direct client, no local queue",
        "smtp_transcript": [],
        "last_smtp_response": None,
        "final_smtp_submission_status": "NOT_SUBMITTED",
        "error": None,
        "failed_stage": None,
        "failed_stage_code": None,
    }
    smtp = smtplib.SMTP(timeout=args.timeout, local_hostname=ehlo)
    stage = "CONNECT"
    try:
        try:
            answers = socket.getaddrinfo(mx, 25, type=socket.SOCK_STREAM)
            report["resolved_ip_addresses"] = sorted({a[4][0] for a in answers})
        except OSError as ex:
            add_step(report, "DNS", extra=f"{type(ex).__name__}: {ex}")
            raise
        code, reply = smtp.connect(mx, 25)
        if smtp.sock:
            report["remote_ip"], _ = smtp.sock.getpeername()[:2]
            report["local_source_ip"], report["local_source_port"] = smtp.sock.getsockname()[:2]
        add_step(report, "220 BANNER", code, reply)
        print(f"BANNER: {code}; remote IP: {report['remote_ip']}", flush=True)
        if code != 220:
            report["final_smtp_submission_status"] = "REMOTE_CONNECT_REJECTED"
            return 1

        stage = "EHLO"
        code, reply = smtp.ehlo()
        add_step(report, "EHLO", code, reply)
        print(f"EHLO: {code}", flush=True)
        report["public_source_ip_observed_by_m365"] = observed_ip_from_ehlo(reply)
        if code != 250:
            report["final_smtp_submission_status"] = "EHLO_REJECTED_NO_MESSAGE_SUBMITTED"
            return 1

        if not args.no_starttls and smtp.has_extn("STARTTLS"):
            stage = "STARTTLS"
            code, reply = smtp.starttls(context=ssl.create_default_context())
            add_step(report, "STARTTLS", code, reply)
            if code != 220:
                report["final_smtp_submission_status"] = "STARTTLS_REJECTED_NO_MESSAGE_SUBMITTED"
                return 1
            report["tls_established"] = True
            print("STARTTLS: OK", flush=True)
            stage = "EHLO after STARTTLS"
            code, reply = smtp.ehlo()
            add_step(report, "EHLO after STARTTLS", code, reply)
            print(f"EHLO after STARTTLS: {code}", flush=True)
            report["public_source_ip_observed_by_m365"] = (
                observed_ip_from_ehlo(reply) or report["public_source_ip_observed_by_m365"]
            )
            if code != 250:
                report["final_smtp_submission_status"] = "TLS_EHLO_REJECTED_NO_MESSAGE_SUBMITTED"
                return 1
        else:
            add_step(report, "STARTTLS SKIPPED", extra="Disabled by option or not offered by server")

        stage = "MAIL FROM"
        code, reply = smtp.mail(sender)
        add_step(report, "MAIL FROM", code, reply)
        print(f"MAIL FROM: {code}", flush=True)
        if code != 250:
            report["final_smtp_submission_status"] = "SENDER_REJECTED_NO_MESSAGE_SUBMITTED"
            return 1

        stage = "RCPT TO"
        code, reply = smtp.rcpt(recipient)
        add_step(report, "RCPT TO", code, reply)
        print(f"RCPT TO: {code}", flush=True)
        if code not in (250, 251):
            report["final_smtp_submission_status"] = "RECIPIENT_REJECTED_NO_MESSAGE_SUBMITTED"
            return 1

        stage = "DATA"
        payload = msg.as_bytes(policy=policy.SMTP)
        code, reply = smtp.data(payload)
        add_step(report, "DATA completion", code, reply)
        print(f"DATA: {code}", flush=True)
        if code == 250:
            report["final_smtp_submission_status"] = "ACCEPTED_BY_REMOTE_SMTP_DELIVERY_NOT_CONFIRMED"
            return 0
        report["final_smtp_submission_status"] = "NOT_ACCEPTED_BY_REMOTE_SMTP"
        return 1
    except (OSError, smtplib.SMTPException, ssl.SSLError) as ex:
        report["error"] = f"{type(ex).__name__}: {ex}"
        report["failed_stage"] = stage
        add_step(report, f"ERROR at {stage}", extra=report["error"])
        if isinstance(ex, smtplib.SMTPResponseException):
            report["failed_stage_code"] = int(ex.smtp_code)
            add_step(report, f"SMTP rejection at {stage}", ex.smtp_code, ex.smtp_error)
        if stage == "DATA" and isinstance(ex, smtplib.SMTPDataError):
            report["final_smtp_submission_status"] = "DATA_REJECTED_BY_REMOTE_SMTP"
        elif stage == "DATA":
            report["final_smtp_submission_status"] = "UNKNOWN_AFTER_DATA_ERROR_MAY_HAVE_BEEN_ACCEPTED"
        elif stage == "RCPT TO":
            report["final_smtp_submission_status"] = "FAILED_BEFORE_DATA_NO_MESSAGE_SUBMITTED"
        else:
            report["final_smtp_submission_status"] = "FAILED_BEFORE_DATA_NO_MESSAGE_SUBMITTED"
        print(f"ERROR at {stage}: {report['error']}", flush=True)
        return 1
    finally:
        report["finished"] = now_pair()
        smtp.close()  # Do not send QUIT after DATA: no extra SMTP step alters evidence.
        outdir = Path(args.report_dir).expanduser().resolve()
        outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(outdir, 0o700)
        stem = f"m365_evidence_{case_id}"
        json_path = outdir / f"{stem}.json"
        txt_path = outdir / f"{stem}.txt"
        write_private(json_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        write_private(txt_path, summarize(report))
        print("\nEvidence saved:")
        print("  JSON:", json_path)
        print("  TXT: ", txt_path)
        print("Final SMTP status:", report["final_smtp_submission_status"])
        print("Local queue status: N/A (direct SMTP client)")
        print("Send TXT to Microsoft. Do not paste actual addresses/IPs into public chat.")


if __name__ == "__main__":
    sys.exit(main())
