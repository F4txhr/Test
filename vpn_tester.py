import re
import socket
import concurrent.futures
import requests
import subprocess
import os

class VPNTester:
    def __init__(self):
       # self.ipapi_cache = {}
        self.timeout = 5  # detik
        self.max_workers = 5
        
    def ekstrak_ip_port(self, url):
        patterns = [
            r'(?:%2F|/)(\d+\.\d+\.\d+\.\d+)-(\d+)',  # /IP-PORT atau %2FIP-PORT
            r'@([\w\.-]+):(\d+)[/?]',  # @domain:port
            r'host=([\w\.-]+).*?port=(\d+)',  # host=... port=...
            r'server":"([^"]+).*?"server_port":(\d+)'  # JSON format
        ]
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                ip, port = match.group(1), match.group(2)
                if not ip.replace('.', '').isdigit():
                    try:
                        ip = socket.gethostbyname(ip)
                    except:
                        continue
                return ip, int(port)
        return None, None

    def get_ip_info(self, ip):
        if ip in self.ipapi_cache:
            return self.ipapi_cache[ip]
        try:
            r = requests.get(f'http://ip-api.com/json/{ip}?fields=countryCode,isp', timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                result = {
                    'provider': data.get('isp', 'Unknown')[:30],
                    'country': data.get('countryCode', 'Unknown')
                }
                self.ipapi_cache[ip] = result
                return result
        except:
            pass
        return {'provider': 'Unknown', 'country': 'Unknown'}

    def test_connection(self, ip_port):
        ip, port = ip_port
        result = {
            'ip': ip,
            'port': port,
            'icmp': '❌',
            'tcp_443': '❌',
            'tcp_custom': '❌',
            'latency': 'N/A',
            'provider': 'Unknown',
            'country': 'Unknown',
            'status': '❌ DEAD'
        }
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future = executor.submit(self.get_ip_info, ip)
                try:
                    isp_info = future.result(timeout=self.timeout)
                    result.update(isp_info)
                except:
                    pass
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                icmp_future = executor.submit(self._test_icmp, ip)
                tcp443_future = executor.submit(self._test_tcp, ip, 443)
                tcp_custom_future = executor.submit(self._test_tcp, ip, port)
                try:
                    icmp, latency = icmp_future.result(timeout=self.timeout)
                    result['icmp'] = '✅' if icmp else '❌'
                    if latency:
                        result['latency'] = f"{latency:.2f} ms"
                except:
                    pass
                try:
                    if tcp443_future.result(timeout=self.timeout):
                        result['tcp_443'] = '✅'
                except:
                    pass
                try:
                    if tcp_custom_future.result(timeout=self.timeout):
                        result['tcp_custom'] = '✅'
                except:
                    pass
            if '✅' in [result['tcp_443'], result['tcp_custom']]:
                result['status'] = '✅ LIVE'
        except Exception as e:
            print(f"Error testing {ip}: {str(e)}")
        return result

    def _test_icmp(self, ip):
        try:
            if os.name == 'nt':
                command = ['ping', '-n', '3', '-w', '2000', ip]
            else:
                command = ['ping', '-c', '3', '-W', '2', ip]
            output = subprocess.run(command, capture_output=True, text=True).stdout
            if 'ttl=' in output.lower() or 'time=' in output.lower():
                latency = re.search(r'=(\d+\.\d+)\s*ms', output)
                return True, float(latency.group(1)) if latency else None
        except:
            pass
        return False, None

    def _test_tcp(self, ip, port):
        try:
            try:
                nc = subprocess.run(['nc', '-z', '-w', '2', ip, str(port)],
                                  capture_output=True)
                if nc.returncode == 0:
                    return True
            except:
                pass
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                return s.connect_ex((ip, port)) == 0
        except:
            return False