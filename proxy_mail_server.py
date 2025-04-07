from aiosmtpd.controller import Controller
from email import message_from_bytes
from email.message import Message
from email.policy import default
import smtplib
import logging
import json
import dns.resolver

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PhishingFilterHandler:
    def __init__(self, internal_server=("localhost", 25)):
        self.internal_server = internal_server

    async def handle_DATA(self, server, session, envelope):
        email_msg = message_from_bytes(envelope.content, policy=default)
        email_body = self.extract_email_body(email_msg)
        subject = email_msg.get("Subject", "")
        
        # Check SPF and DMARC for phishing detection
        domain = envelope.mail_from.split('@')[-1]
        spf_info = self.check_spf(domain)
        dmarc_info = self.check_dmarc(domain)
        is_phishing = not (spf_info and dmarc_info)  # Phishing if either SPF or DMARC is missing

        try:
            if is_phishing:
                logger.warning(f"Flagged phishing email from {envelope.mail_from}")
                # Log phishing email details in JSON format
                self.log_phishing_email(
                    mail_from=envelope.mail_from,
                    rcpt_tos=envelope.rcpt_tos,
                    subject=subject,
                    email_content=email_body,
                    spf_info=spf_info,
                    dmarc_info=dmarc_info
                )
                modified_msg = self.add_warning_to_email(email_msg)
                modified_content = modified_msg.as_bytes()
            else:
                modified_content = envelope.content

            # Forward the email (modified or original)
            self.forward_email(envelope.mail_from, envelope.rcpt_tos, modified_content)
            return '250 OK'
        except Exception as e:
            logger.error(f"Forwarding failed: {str(e)}")
            return '451 Temporary error'

    def extract_email_body(self, msg):
        """Extracts text content from the email."""
        body = []
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                payload = part.get_payload(decode=True)
                if payload:
                    body.append(payload.decode(errors='replace'))
        return " ".join(body).strip()

    def add_warning_to_email(self, original_msg):
        """Adds a phishing warning banner to the email content."""
        modified_msg = Message()
        modified_msg.set_charset('utf-8')

        # Copy headers (except BCC, Date, etc.)
        for header in ["From", "To", "Subject", "Content-Type"]:
            if header in original_msg:
                modified_msg[header] = original_msg[header]

        # Add warning to the subject
        original_subject = original_msg.get("Subject", "")
        modified_msg["Subject"] = f"[SUSPICIOUS] {original_subject}"

        # Build the modified body
        warning_plain = (
            "*** WARNING: This email was flagged as suspicious. "
            "Do not click links or download attachments. ***\n\n"
        )
        warning_html = (
            '<div style="color: red; background: #ffe6e6; padding: 10px; border: 2px solid red; '
            'font-family: Arial, sans-serif; margin: 10px 0;">'
            '⚠ WARNING: This email was flagged as suspicious. '
            'Do not click links or download attachments.'
            '</div>'
        )

        # Handle multipart emails
        if original_msg.is_multipart():
            modified_msg.make_mixed()
            for part in original_msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True).decode(errors='replace')
                    part.set_payload(warning_plain + payload)
                elif part.get_content_type() == "text/html":
                    payload = part.get_payload(decode=True).decode(errors='replace')
                    part.set_payload(warning_html + payload)
                modified_msg.attach(part)
        else:
            # Handle single-part emails
            content_type = original_msg.get_content_type()
            payload = original_msg.get_payload(decode=True).decode(errors='replace')
            if content_type == "text/plain":
                modified_msg.set_payload(warning_plain + payload)
            elif content_type == "text/html":
                modified_msg.set_payload(warning_html + payload)
            else:
                modified_msg.set_payload(payload)

        return modified_msg

    def forward_email(self, mail_from, rcpt_tos, content):
        """Forward the email to the internal SMTP server."""
        with smtplib.SMTP(*self.internal_server) as smtp:
            smtp.sendmail(mail_from, rcpt_tos, content)

    def check_spf(self, domain):
        """Check for SPF records for the given domain."""
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    return txt
            return None
        except Exception as e:
            logger.debug(f"SPF check failed for {domain}: {e}")
            return None

    def check_dmarc(self, domain):
        """Check for DMARC records for the given domain."""
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    return txt
            return None
        except Exception as e:
            logger.debug(f"DMARC check failed for {domain}: {e}")
            return None

    def log_phishing_email(self, mail_from, rcpt_tos, subject, email_content, spf_info, dmarc_info):
        """Log phishing email details to a JSON log file."""
        log_entry = {
            "from": mail_from,
            "to": rcpt_tos,
            "subject": subject,
            "email_content": email_content,
            "spf_info": spf_info,
            "dmarc_info": dmarc_info
        }
        try:
            with open("phishing_log.json", "a") as f:
                json.dump(log_entry, f)
                f.write("\n")
            logger.info("Phishing email logged successfully.")
        except Exception as e:
            logger.error(f"Error writing to log file: {e}")

if __name__ == "__main__":
    handler = PhishingFilterHandler(internal_server=("localhost", 1025))
    controller = Controller(handler, hostname='0.0.0.0', port=25)
    controller.start()
    logger.info("Proxy server running. Press Ctrl+C to stop.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        controller.stop()