import json
import urllib.parse
import base64
import re
import socket
import requests
from utils_extract import ensure_path_ip_port

class VPNConverter:
    def __init__(self, github_repo="", github_token="", template_file="", output_prefix="", download_dir=""):
        self.GITHUB_REPO = github_repo
        self.GITHUB_TOKEN = github_token
        self.TEMPLATE_FILE = template_file
        self.OUTPUT_PREFIX = output_prefix
        self.DOWNLOAD_DIR = download_dir

    def get_github_files(self):
        url = f"https://api.github.com/repos/{self.GITHUB_REPO}/contents/"
        headers = {"Authorization": f"token {self.GITHUB_TOKEN}"} if self.GITHUB_TOKEN else {}
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            return []
        return [f['name'] for f in r.json() if f['name'].endswith('.txt') or f['name'].endswith('.json')]

    def get_file_from_github(self, filename):
        url = f"https://api.github.com/repos/{self.GITHUB_REPO}/contents/{filename}"
        headers = {"Authorization": f"token {self.GITHUB_TOKEN}"} if self.GITHUB_TOKEN else {}
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            return None
        content = base64.b64decode(r.json()['content']).decode('utf-8')
        try:
            return json.loads(content)
        except Exception:
            try:
                import yaml
                return yaml.safe_load(content)
            except Exception:
                return content

    def upload_to_github(self, config, filename, message):
        url = f"https://api.github.com/repos/{self.GITHUB_REPO}/contents/{filename}"
        headers = {
            "Authorization": f"token {self.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        r = requests.get(url, headers=headers)
        sha = None
        if r.status_code == 200:
            sha = r.json().get("sha")
        content = base64.b64encode(json.dumps(config, indent=2, ensure_ascii=False).encode()).decode()
        data = {"message": message, "content": content}
        if sha:
            data["sha"] = sha
        r = requests.put(url, headers=headers, json=data)
        print(f"API upload response: {r.status_code} {r.text}")
        if r.status_code in [200, 201]:
            return f"✅ Sukses upload {filename}"
        return f"❌ Gagal upload {filename}: {r.text}"

    def parse_vmess_link(self, link):
        try:
            b64 = link[8:]
            padded = b64 + '=' * (-len(b64) % 4)
            decoded = base64.urlsafe_b64decode(padded).decode('utf-8')
            return json.loads(decoded)
        except Exception:
            return None

    def parse_shadowsocks_link(self, ss_link):
        try:
            if not ss_link.startswith("ss://"):
                return None
            link = ss_link[5:]
            tag = ""
            if '#' in link:
                link, tag = link.split('#', 1)
                tag = urllib.parse.unquote(tag)
            plugin = ""
            plugin_opts = ""
            if '/?' in link:
                link, plugin_str = link.split('/?', 1)
                params = urllib.parse.parse_qs(plugin_str)
                plugin = params.get('plugin', [""])[0]
                plugin_opts = plugin
            if '@' in link:
                userinfo_enc, server = link.split('@', 1)
                userinfo_enc = urllib.parse.unquote(userinfo_enc)
                padded = userinfo_enc + '=' * (-len(userinfo_enc) % 4)
                userinfo = base64.urlsafe_b64decode(padded).decode('utf-8')
                if ':' not in userinfo or ':' not in server:
                    return None
                method, password = userinfo.split(':', 1)
                host, port = server.split(':', 1)
                m = re.match(r'(\d+)', port)
                port = m.group(1) if m else "443"
            else:
                padded = link + '=' * (-len(link) % 4)
                decoded = base64.urlsafe_b64decode(padded).decode('utf-8')
                if '@' in decoded and ':' in decoded:
                    method_pass, server = decoded.rsplit('@', 1)
                    method, password = method_pass.split(':', 1)
                    host, port = server.split(':', 1)
                    m = re.match(r'(\d+)', port)
                    port = m.group(1) if m else "443"
                else:
                    return None
            raw_path = f"/{host}-{port}"
            path = ensure_path_ip_port(raw_path)
            if plugin:
                plugin_opts = f"mux=0;path={path};host={host};tls=1"
            return {
                "type": "shadowsocks",
                "tag": tag or host,
                "server": host,
                "server_port": int(port),
                "method": method,
                "password": password,
                "plugin": plugin,
                "plugin_opts": plugin_opts,
                "domain_strategy": "ipv4_only",
                "path": path,
            }
        except Exception as e:
            print(f"Error parsing Shadowsocks link: {e} | link: {ss_link}")
            return None

    def convert_link_to_singbox_outbound(self, link_str):
        try:
            link_str = link_str.strip()
            outbound_config = None
            provider, country = "", ""
            if link_str.startswith("vmess://"):
                vmess_data = self.parse_vmess_link(link_str)
                if not vmess_data:
                    return None
                host = vmess_data.get("add", "")
                port = str(vmess_data.get("port", 443))
                m = re.match(r'(\d+)', port)
                port = m.group(1) if m else "443"
                outbound_config = {
                    "type": "vmess",
                    "tag": vmess_data.get("ps", host),
                    "server": host,
                    "server_port": int(port),
                    "uuid": vmess_data.get("id", ""),
                    "alter_id": int(vmess_data.get("aid", 0)),
                    "security": vmess_data.get("scy", "auto"),
                    "network": vmess_data.get("net", "tcp"),
                    "domain_strategy": "ipv4_only",
                    "multiplex": {
                        "protocol": "smux",
                        "max_streams": 32
                    }
                }
                tls_enabled = vmess_data.get("tls", "") == "tls"
                tls_dict = {
                    "enabled": tls_enabled,
                    "server_name": vmess_data.get("host", host),
                    "insecure": True
                }
                if vmess_data.get("fp"):
                    tls_dict["utls"] = {"enabled": True, "fingerprint": vmess_data.get("fp")}
                outbound_config["tls"] = tls_dict
                if vmess_data.get("net") == "ws":
                    outbound_config["transport"] = {
                        "type": "ws",
                        "path": ensure_path_ip_port(f"/{host}-{port}"),
                        "headers": {"Host": vmess_data.get("host", host)}
                    }
                elif vmess_data.get("net") == "grpc":
                    outbound_config["transport"] = {
                        "type": "grpc",
                        "service_name": vmess_data.get("path", "").strip('/')
                    }
                tag = outbound_config.get("tag", "")
                m = re.search(r"\((\w{2})\)\s*([^(]+)", tag)
                if m:
                    country = m.group(1)
                    provider = m.group(2).strip()
                outbound_config["provider"] = provider
                outbound_config["country"] = country
                return outbound_config
            elif link_str.startswith("vless://"):
                url_no_schema = link_str[len("vless://"):]
                userinfo, rest = url_no_schema.split("@", 1)
                if "?" in rest:
                    serverhost, paramfrag = rest.split("?", 1)
                else:
                    serverhost, paramfrag = rest, ""
                if "#" in paramfrag:
                    params, frag = paramfrag.split("#", 1)
                else:
                    params, frag = paramfrag, ""
                if ":" in serverhost:
                    host, port = serverhost.split(":", 1)
                else:
                    host, port = serverhost, "443"
                m = re.match(r'(\d+)', port)
                port = m.group(1) if m else "443"
                query_params = urllib.parse.parse_qs(params)
                tag = urllib.parse.unquote(frag) if frag else f"{host}"
                outbound_config = {
                    "type": "vless",
                    "tag": tag,
                    "domain_strategy": "ipv4_only",
                    "server": host,
                    "server_port": int(port),
                    "uuid": userinfo,
                    "tls": {
                        "enabled": query_params.get("security", [""])[0] == "tls",
                        "server_name": query_params.get("host", [host])[0],
                        "insecure": True
                    },
                    "multiplex": {
                        "protocol": "smux",
                        "max_streams": 32
                    }
                }
                network_type = query_params.get("type", ["tcp"])[0]
                if network_type == "ws":
                    outbound_config["transport"] = {
                        "type": "ws",
                        "path": ensure_path_ip_port(f"/{host}-{port}"),
                        "headers": {
                            "Host": query_params.get("host", [host])[0]
                        }
                    }
                elif network_type == "grpc":
                    outbound_config["transport"] = {
                        "type": "grpc",
                        "service_name": query_params.get("serviceName", [""])[0]
                    }
                if "fp" in query_params:
                    outbound_config["tls"]["utls"] = {"enabled": True, "fingerprint": query_params["fp"][0]}
                m = re.search(r"\((\w{2})\)\s*([^(]+)", tag)
                if m:
                    country = m.group(1)
                    provider = m.group(2).strip()
                outbound_config["provider"] = provider
                outbound_config["country"] = country
                return outbound_config
            elif link_str.startswith("trojan://"):
                url_no_schema = link_str[len("trojan://"):]
                userinfo, rest = url_no_schema.split("@", 1)
                if "?" in rest:
                    serverhost, paramfrag = rest.split("?", 1)
                else:
                    serverhost, paramfrag = rest, ""
                if "#" in paramfrag:
                    params, frag = paramfrag.split("#", 1)
                else:
                    params, frag = paramfrag, ""
                if ":" in serverhost:
                    host, port = serverhost.split(":", 1)
                else:
                    host, port = serverhost, "443"
                m = re.match(r'(\d+)', port)
                port = m.group(1) if m else "443"
                query_params = urllib.parse.parse_qs(params)
                tag = urllib.parse.unquote(frag) if frag else f"{host}"
                path = ensure_path_ip_port(f"/{host}-{port}")
                transport = None
                if query_params.get("type", [""]) == ["ws"]:
                    transport = {
                        "type": "ws",
                        "path": path,
                        "headers": {
                            "Host": query_params.get("host", [host])[0]
                        },
                        "early_data_header_name": "Sec-WebSocket-Protocol"
                    }
                outbound_config = {
                    "type": "trojan",
                    "tag": tag,
                    "server": host,
                    "server_port": int(port),
                    "password": userinfo,
                    "multiplex": {
                        "protocol": "smux",
                        "max_streams": 32
                    },
                    "domain_strategy": "ipv4_only",
                    "tls": {
                        "enabled": query_params.get("security", [""])[0] == "tls",
                        "server_name": query_params.get("sni", [host])[0],
                        "insecure": True
                    }
                }
                if transport:
                    outbound_config["transport"] = transport
                outbound_config["path"] = path
                m = re.search(r"\((\w{2})\)\s*([^(]+)", tag)
                if m:
                    country = m.group(1)
                    provider = m.group(2).strip()
                outbound_config["provider"] = provider
                outbound_config["country"] = country
                return outbound_config
            elif link_str.startswith("ss://"):
                outbound_config = self.parse_shadowsocks_link(link_str)
                if not outbound_config:
                    return None
                tag = outbound_config.get("tag", "")
                m = re.search(r"\((\w{2})\)\s*([^(]+)", tag)
                if m:
                    country = m.group(1)
                    provider = m.group(2).strip()
                outbound_config["provider"] = provider
                outbound_config["country"] = country
                return outbound_config
            else:
                return None
        except Exception as e:
            print(f"Error saat mengkonversi link {link_str}: {e}")
            return None

def test_node(node):
    # Tes menggunakan IP hasil path kalau ada, fallback ke server/domain
    ip = node.get("server")
    port = node.get("server_port")
    m = re.match(r"/(\d{1,3}(?:\.\d{1,3}){3})-(\d+)", str(node.get("path", "")))
    if m:
        ip = m.group(1)
        port = int(m.group(2))
    try:
        s = socket.create_connection((ip, port), timeout=2)
        s.close()
        return True
    except Exception:
        return False

def get_country_isp(ip):
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}?fields=countryCode,isp', timeout=4)
        if r.status_code == 200:
            data = r.json()
            country = data.get('countryCode', 'XX')
            isp = data.get('isp', 'Unknown')
            return country, isp
    except Exception:
        pass
    return "XX", "Unknown"

def generate_final_tag(country, isp, idx):
    return f"{country} {isp} {idx:02d}"

def process_links(links):
    outbounds = []
    idx = 1
    converter = VPNConverter()
    for link in links:
        node = converter.convert_link_to_singbox_outbound(link)
        if node and test_node(node):
            ip = node.get("server")
            # Untuk info negara/ISP, tetap gunakan IP dari path kalau ada
            m = re.match(r"/(\d{1,3}(?:\.\d{1,3}){3})-(\d+)", str(node.get("path", "")))
            if m:
                ip = m.group(1)
            country, isp = get_country_isp(ip)
            tag = generate_final_tag(country, isp, idx)
            node["tag"] = tag
            node["provider"] = isp
            node["country"] = country
            outbounds.append(node)
            idx += 1
    return outbounds

if __name__ == "__main__":
    links = [
        # Masukkan link vmess, vless, trojan, ss
        "vmess://eyJhZGQiOiIxLjEuMS4xIiwicG9ydCI6IjQ0MyIsImlkIjoiYTAwMDAwMC1hYWJiLTAwMDAiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwidGxzIjoidGxzIiwicHMiOiJUZXN0IFZNRVNTIn0=",
        "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0cGFzc0AxLjEuMS4yOjQ0Mw==#Test-SS",
        "trojan://password@1.1.1.3:443?sni=example.com#Test-Trojan",
        "vless://uuid@1.1.1.4:443?type=ws&security=tls#Test-VLESS"
    ]
    hasil = process_links(links)
    print(json.dumps(hasil, indent=2, ensure_ascii=False))