import re
import socket

def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host  # fallback: kembalikan host apa adanya jika gagal

def ensure_path_ip_port(path):
    """
    Jika path sudah /ip-port, return seperti itu.
    Jika path masih /domain-port, resolve ke ip, dan return /ip-port.
    Jika gagal, return path as is.
    """
    ip_port_match = re.match(r'/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d+)', path)
    if ip_port_match:
        return path
    domain_port_match = re.match(r'/([A-Za-z0-9\.\-]+)-(\d+)', path)
    if domain_port_match:
        domain = domain_port_match.group(1)
        port = domain_port_match.group(2)
        ip = resolve_ip(domain)
        return f"/{ip}-{port}"
    return path  # fallback jika format tidak cocok

def extract_ip_port_from_path(path):
    """
    Return (ip, port) jika path /ip-port atau /domain-port (akan di-resolve).
    Jika gagal, return (None, None)
    """
    ip_port_match = re.match(r'/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d+)', path)
    if ip_port_match:
        return ip_port_match.group(1), ip_port_match.group(2)
    domain_port_match = re.match(r'/([A-Za-z0-9\.\-]+)-(\d+)', path)
    if domain_port_match:
        domain = domain_port_match.group(1)
        port = domain_port_match.group(2)
        ip = resolve_ip(domain)
        return ip, port
    return None, None