import json
import urllib.parse
import base64
import requests
import re
import yaml

class VPNConverter:
    def __init__(self, github_repo, github_token, template_file, output_prefix, download_dir):
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
        """
        Ambil file dari github, decode base64, parsing otomatis ke JSON/YAML jika bisa.
        """
        url = f"https://api.github.com/repos/{self.GITHUB_REPO}/contents/{filename}"
        headers = {"Authorization": f"token {self.GITHUB_TOKEN}"} if self.GITHUB_TOKEN else {}
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            return None
        content = base64.b64decode(r.json()['content']).decode('utf-8')
        # Otomatis parse JSON/YAML, fallback string mentah
        try:
            return json.loads(content)
        except Exception:
            try:
                return yaml.safe_load(content)
            except Exception:
                return content  # Kembalikan string mentah jika tidak bisa di-parse

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
        print(f"API upload response: {r.status_code} {r.text}")  # Logging/debug
        if r.status_code in [200, 201]:
            return f"✅ Sukses upload {filename}"
        return f"❌ Gagal upload {filename}: {r.text}"

    def parse_vmess_link(self, vmess_link):
        try:
            if not vmess_link.startswith("vmess://"):
                return None
            encoded_data = vmess_link[len("vmess://"):]
            missing_padding = len(encoded_data) % 4
            if missing_padding:
                encoded_data += '=' * (4 - missing_padding)
            decoded_data = base64.b64decode(encoded_data).decode('utf-8')
            return json.loads(decoded_data)
        except Exception as e:
            print(f"Error parsing VMess link (base64/JSON issue): {e}")
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
                outbound_config = {
                    "type": "vmess",
                    "tag": vmess_data.get("ps", vmess_data.get("add", "")),
                    "server": vmess_data.get("add", ""),
                    "server_port": int(vmess_data.get("port", 443)),
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
                    "server_name": vmess_data.get("host", outbound_config["server"]),
                    "insecure": True
                }
                if vmess_data.get("fp"):
                    tls_dict["utls"] = {"enabled": True, "fingerprint": vmess_data.get("fp")}
                outbound_config["tls"] = tls_dict
                if vmess_data.get("net") == "ws":
                    outbound_config["transport"] = {
                        "type": "ws",
                        "path": vmess_data.get("path", ""),
                        "headers": {"Host": vmess_data.get("host", outbound_config["server"])}
                    }
                elif vmess_data.get("net") == "grpc":
                    outbound_config["transport"] = {
                        "type": "grpc",
                        "service_name": vmess_data.get("path", "").strip('/')
                    }
                # PATCH: parse provider/country from tag if present
                tag = outbound_config.get("tag", "")
                m = re.search(r"\((\w{2})\)\s*([^(]+)", tag)
                if m:
                    country = m.group(1)
                    provider = m.group(2).strip()
                outbound_config["provider"] = provider
                outbound_config["country"] = country
                # PATCH: simpan path ke format /IP-PORT jika ada
                if outbound_config.get("server") and outbound_config.get("server_port"):
                    outbound_config["path"] = f"/{outbound_config['server']}-{outbound_config['server_port']}"
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
                        "path": query_params.get("path", [""])[0],
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
                # PATCH: parse provider/country from tag if present
                m = re.search(r"\((\w{2})\)\s*([^(]+)", tag)
                if m:
                    country = m.group(1)
                    provider = m.group(2).strip()
                outbound_config["provider"] = provider
                outbound_config["country"] = country
                if outbound_config.get("server") and outbound_config.get("server_port"):
                    outbound_config["path"] = f"/{outbound_config['server']}-{outbound_config['server_port']}"
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
                query_params = urllib.parse.parse_qs(params)
                tag = urllib.parse.unquote(frag) if frag else f"{host}"
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
                # PATCH: parse provider/country from tag if present
                m = re.search(r"\((\w{2})\)\s*([^(]+)", tag)
                if m:
                    country = m.group(1)
                    provider = m.group(2).strip()
                outbound_config["provider"] = provider
                outbound_config["country"] = country
                if outbound_config.get("server") and outbound_config.get("server_port"):
                    outbound_config["path"] = f"/{outbound_config['server']}-{outbound_config['server_port']}"
                return outbound_config

            else:
                return None
        except Exception as e:
            print(f"Error saat mengkonversi link {link_str}: {e}")
            return None