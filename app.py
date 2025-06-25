import dash
from dash import dcc, html, Input, Output, State, ctx
import threading
import json
import copy
from datetime import datetime
import re
import logging
from urllib.parse import unquote
import requests
import base64
from script import VPNConverter
from config import GITHUB_REPO, GITHUB_TOKEN, TEMPLATE_FILE, OUTPUT_PREFIX, DOWNLOAD_DIR
from vpn_tester import VPNTester
from country_flag import (
    country_to_flag,
    get_country_name,
    format_and_clean_nodes,
    parse_provider_from_tag,
    get_country_code_from_tag
)

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)

def extract_ip_port_from_account(cfg):
    if "transport" in cfg and "path" in cfg["transport"]:
        path = cfg["transport"]["path"]
        m = re.match(r"/([\d\.]+)-(\d+)", path)
        if m:
            return m.group(1), int(m.group(2))
        else:
            logging.warning(f"[extract_ip_port_from_account] Path {path} in 'transport' does not match pattern /ip-port")
    if "path" in cfg:
        path = cfg["path"]
        m = re.match(r"/([\d\.]+)-(\d+)", path)
        if m:
            return m.group(1), int(m.group(2))
        else:
            logging.warning(f"[extract_ip_port_from_account] Path {path} does not match pattern /ip-port")
    logging.warning(f"[extract_ip_port_from_account] No path found in node: {cfg.get('tag', str(cfg))}")
    return None, None

def parse_tag_country_provider_from_link(link):
    m = re.search(r'#(.+)$', link)
    tag = unquote(m.group(1)).replace('\r', '').replace('\n', '') if m else ""
    m2 = re.search(r"\((\w{2})\)\s*([^(]+)", tag)
    country_code = m2.group(1) if m2 else ""
    provider = m2.group(2).strip() if m2 else ""
    if not provider and tag:
        provider = parse_provider_from_tag(tag)
    return tag, country_code, provider

def progress_bar(progress, total):
    pct = int(progress / total * 100) if total else 0
    return html.Div([
        html.Div(style={
            "width": f"{pct}%",
            "background": "#007bff",
            "height": "20px",
            "transition": "width 0.3s"
        })
    ], style={
        "width": "100%",
        "background": "#e9ecef",
        "borderRadius": "8px",
        "overflow": "hidden",
        "marginTop": "8px",
        "marginBottom": "8px"
    })

def status_dot(is_ok: bool, pulse=False):
    color = "#28c76f" if is_ok else "#EA5455"
    classes = "dot-pulse" if pulse else ""
    return html.Div(className=classes, style={
        "width": "14px",
        "height": "14px",
        "borderRadius": "50%",
        "display": "inline-block",
        "background": color,
        "margin": "auto"
    })

def icmp_tcp_dotlist(stat, pulse=False):
    def dot(ok):
        color = "#28c76f" if ok else "#EA5455"
        cls = "dot-pulse" if pulse else ""
        return html.Div(className=cls, style={
            "width": "10px", "height": "10px", "borderRadius": "50%",
            "background": color, "display": "block", "margin": "2px auto"
        })
    return html.Div([
        dot(stat.get('icmp', '') == '✅'),
        dot(stat.get('tcp_443', '') == '✅'),
        dot(stat.get('tcp_custom', '') == '✅'),
    ], style={
        "display": "flex", "flexDirection": "column", "alignItems": "center", "height": "36px"
    })

# --- Tambahkan fungsi upload_to_github ke VPNConverter ---
def upload_to_github(self, config, file_name, message):
    owner, repo = GITHUB_REPO.split("/")
    token = GITHUB_TOKEN
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_name}"
    headers = {"Authorization": f"token {token}"}

    # 1. Ambil sha file lama jika ada
    r = requests.get(url, headers=headers)
    sha = r.json().get("sha") if r.status_code == 200 else None

    # 2. Siapkan data
    content = base64.b64encode(json.dumps(config, indent=2, ensure_ascii=False).encode("utf-8")).decode("utf-8")
    data = {"message": message, "content": content}
    if sha:
        data["sha"] = sha

    r = requests.put(url, headers=headers, json=data)
    if not r.ok:
        logging.error(f"Gagal upload ke GitHub: {r.text}")
        raise Exception(f"Gagal upload ke GitHub: {r.text}")
    logging.info(f"Berhasil upload ke GitHub sebagai {file_name}")
    return r.json()
# Tambahkan ke class
VPNConverter.upload_to_github = upload_to_github

converter = VPNConverter(
    github_repo=GITHUB_REPO,
    github_token=GITHUB_TOKEN,
    template_file=TEMPLATE_FILE,
    output_prefix=OUTPUT_PREFIX,
    download_dir=DOWNLOAD_DIR
)
tester = VPNTester()

app = dash.Dash(
    __name__,
    external_stylesheets=[
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css",
        "/assets/custom-style.css"
    ],
    assets_folder="assets",
    suppress_callback_exceptions=True
)
app.title = "VPN Tester & Auto Tag"

progress_state = {
    "progress": 0,
    "total": 1,
    "running": False,
    "results": [],
    "json_results": [],
    "base_config": {},
    "file_name": "",
    "stat": {},
    "final_config": {},
    "last_progress": -1
}

app.layout = html.Div([
    html.Div(className="full-bg"),
    html.Div([
        html.Div([
            html.I(className="fas fa-shield-alt header-icon"),
            html.Span("VPN Tester & Auto Tag", className="header-title")
        ], className="header"),
        html.Div([
            html.Div([
                html.Label("Pilih file config dari GitHub untuk update:", className="label"),
                dcc.Dropdown(
                    id="github-config-dropdown",
                    options=[],
                    placeholder="Pilih config dari GitHub atau buat baru",
                    className="select"
                ),
            ], className="form-group"),
            html.Div([
                html.Label("Tambahkan link akun VPN baru (opsional, satu per baris):", className="label"),
                dcc.Textarea(
                    id="vpn-link",
                    rows=4,
                    className="textarea",
                    placeholder="Paste link VPN di sini..."
                )
            ], className="form-group"),
            html.Button(
                [html.I(className="fas fa-bolt mr-2"), "Test & Convert"],
                id="preview-btn",
                className="btn btn-primary btn-block mb-4"
            ),
            dcc.Interval(id="progress-interval", interval=1000, n_intervals=0, disabled=True),
            html.Div(id="progress-div", className="progress-div"),
            dcc.Store(id="table-store"),
            dcc.Store(id="stat-store"),
            html.Div(id="preview-result", className="results"),
            html.Div(id="statistic-result", className="statistic-result"),
            html.Div([
                html.Button(
                    [html.I(className="fas fa-cloud-upload-alt mr-2"), "Upload ke GitHub"],
                    id="upload-btn", className="btn btn-secondary"
                ),
                html.Button(
                    [html.I(className="fas fa-download mr-2"), "Download Config"],
                    id="download-btn", className="btn btn-success"
                ),
                html.Button(
                    [html.I(className="fas fa-table mr-2"), "Download JSON Hasil Test"],
                    id="download-json-btn", className="btn btn-info"
                ),
                dcc.Download(id="download-config"),
                dcc.Download(id="download-json")
            ], className="action-buttons"),
            html.Div(id="upload-result", className="mt-4")
        ], className="card"),
    ], className="container"),
    html.Div([
        html.P("VPN Converter - by F4txhr", className="footer")
    ])
])

@app.callback(
    Output("github-config-dropdown", "options"),
    Input("github-config-dropdown", "id"),
)
def load_github_config_options(_):
    try:
        files = converter.get_github_files()
        logging.info(f"Loaded file list from GitHub: {files}")
        if not files:
            files = []
    except Exception as e:
        logging.error(f"Failed to load config file list: {e}")
        files = []
    return (
        [{"label": f, "value": f} for f in files] +
        [{"label": "➕ Buat file baru (txt)", "value": "__NEW__"}]
    )

def start_batch_test(configs, tag_list, provider_list, country_list):
    logging.info(f"[start_batch_test] Mulai batch test dengan {len(configs)} node")
    filtered = []
    for idx, (cfg, tag, provider, country) in enumerate(zip(configs, tag_list, provider_list, country_list)):
        ip, port = extract_ip_port_from_account(cfg)
        logging.info(f"[start_batch_test] Node #{idx+1}: tag={tag}, ip={ip}, port={port}, provider={provider}, country={country}")
        if not ip or not port:
            logging.warning(f"[start_batch_test] Node {tag} dilewati, tidak ada IP/Port.")
            continue
        if provider.strip().upper() == "IL" or country.strip().upper() == "IL":
            logging.warning(f"[start_batch_test] Node {tag} dilewati, provider/country IL.")
            continue
        filtered.append((cfg, tag, provider, country)

        )
    logging.info(f"[start_batch_test] Setelah filter, tersisa {len(filtered)} node.")
    progress_state["progress"] = 0
    progress_state["total"] = len(filtered)
    progress_state["results"] = [None]*len(filtered)
    progress_state["running"] = True
    progress_state["last_progress"] = -1

    def run():
        for idx, (cfg, tag, provider, country) in enumerate(filtered):
            ip, port = extract_ip_port_from_account(cfg)
            try:
                logging.info(f"[start_batch_test:thread] Test node #{idx+1}: {ip}:{port} ({tag})")
                test_result = tester.test_connection((ip, port))
                logging.info(f"[start_batch_test:thread] Hasil test node #{idx+1}: {test_result}")
            except Exception as e:
                logging.error(f"[start_batch_test:thread] Error test node #{idx+1}: {e}")
                test_result = {
                    'ip': ip, 'port': port, 'provider': provider, 'country': country,
                    'icmp': '❌', 'tcp_443': '❌', 'tcp_custom': '❌', 'latency': 'N/A', 'status': '❌ DEAD', 'tag': tag
                }
            test_result['ip'] = ip
            test_result['port'] = port
            test_result['provider'] = provider if provider else "-"
            test_result['country'] = country if country else "-"
            test_result['tag'] = tag if tag else "-"
            progress_state["results"][idx] = (cfg, test_result)
            progress_state["progress"] = idx + 1
        progress_state["running"] = False
        progress_state["json_results"] = [t[1] for t in progress_state["results"] if isinstance(t, tuple) and t is not None and len(t) == 2]
        logging.info("[start_batch_test:thread] Batch test selesai.")

    threading.Thread(target=run, daemon=True).start()

def make_stat_and_rekom(results):
    live = [r for r in results if r['status'] == '✅ LIVE']
    avg_latency = (
        sum(float(r['latency'].split()[0].replace(",", ".")) for r in live if r['latency'] != 'N/A') / max(1, len(live))
        if live else 0.0
    )
    rekom = None
    if live:
        rekom = min(live, key=lambda x: float(x['latency'].split()[0].replace(",", ".")) if x['latency'] != 'N/A' else 9999)
    return {
        "live_count": len(live),
        "total": len(results),
        "avg_latency": avg_latency,
        "rekom": rekom
    }

def render_modern_table(results):
    last_index = progress_state.get("last_progress", -1)
    headers = ["Status", "IP", "Country", "Latency", "Tag", ""]
    rows = []
    for idx, stat in enumerate(results):
        live = stat.get('status', '').startswith('✅')
        is_new = idx > last_index
        row_class = "new-row" if is_new else ""
        stat_dot = status_dot(live, pulse=is_new)
        dots = icmp_tcp_dotlist(stat, pulse=is_new)
        country_code = stat.get('country', "")
        provider = stat.get('provider', "")
        country_flag = country_to_flag(country_code)
        tag_text = provider
        rows.append(html.Tr([
            html.Td([stat_dot], style={"textAlign": "center"}),
            html.Td(stat.get('ip', "")),
            html.Td(country_flag),
            html.Td(stat.get('latency', "")),
            html.Td(tag_text),
            html.Td(dots, style={"textAlign": "center"})
        ], className=row_class))
    progress_state["last_progress"] = len(results) - 1
    return html.Table([
        html.Thead(html.Tr([html.Th(h, style={"fontWeight": "bold", "textAlign": "center"}) for h in headers])),
        html.Tbody(rows)
    ], className="modern-table")

@app.callback(
    Output("preview-result", "children"),
    Input("table-store", "data")
)
def render_table_from_store(data):
    if not data: return ""
    return render_modern_table(data)

@app.callback(
    Output("statistic-result", "children"),
    Input("stat-store", "data")
)
def render_stat_from_store(data):
    if not data: return ""
    stat_info = data
    return html.Div([
        html.P(f"Total Node: {stat_info['total']}"),
        html.P(f"Live: {stat_info['live_count']}"),
        html.P(f"Rata-rata Latency: {stat_info['avg_latency']:.2f} ms"),
        html.P(f"Rekomendasi: {stat_info['rekom']['tag'] if stat_info['rekom'] else '-'}")
    ], style={"marginTop": 16})

@app.callback(
    Output("progress-div", "children"),
    Output("table-store", "data"),
    Output("stat-store", "data"),
    Output("upload-result", "children"),
    Output("download-config", "data"),
    Output("download-json", "data"),
    Output("progress-interval", "disabled"),
    Input("preview-btn", "n_clicks"),
    Input("progress-interval", "n_intervals"),
    Input("upload-btn", "n_clicks"),
    Input("download-btn", "n_clicks"),
    Input("download-json-btn", "n_clicks"),
    State("github-config-dropdown", "value"),
    State("vpn-link", "value"),
    State("table-store", "data"),
    State("stat-store", "data"),
    prevent_initial_call=True
)
def main_callback(preview_click, interval_n, upload_click, download_click, download_json_click, github_file, vpn_links, prev_table, prev_stat):
    triggered = ctx.triggered_id

    def load_template_config():
        with open("singbox-template.txt", encoding="utf-8") as f:
            return json.load(f)

    if triggered == "preview-btn":
        file_name = "config.txt"
        if github_file == "__NEW__":
            now = datetime.now()
            file_name = f"VortexNet-{now.strftime('%Y%m%d-%H%M%S')}.txt"
            base_config = load_template_config()
        else:
            base_config = converter.get_file_from_github(github_file)
            if not base_config or "outbounds" not in base_config or len(base_config) <= 1:
                template = load_template_config()
                template["outbounds"] = base_config.get("outbounds", []) if base_config else []
                base_config = template

        semua = base_config.get("outbounds", [])
        akun_lama = [o for o in semua if o.get("type") in ["trojan", "vless", "vmess"]]
        user_links = [l.strip() for l in (vpn_links or "").splitlines() if l.strip()]

        akun_baru, tag_baru, provider_baru, country_baru = [], [], [], []
        for l in user_links:
            o = converter.convert_link_to_singbox_outbound(l)
            if o:
                tag, country_code, provider = parse_tag_country_provider_from_link(l)
                if provider.strip().upper() == "IL" or country_code.strip().upper() == "IL":
                    continue
                o["provider"] = provider
                o["country"] = country_code
                akun_baru.append(o)
                tag_baru.append(tag)
                provider_baru.append(provider)
                country_baru.append(country_code)
            else:
                logging.warning(f"[main_callback] Gagal convert link: {l}")

        filtered_lama, tag_lama, provider_lama, country_lama = [], [], [], []
        for o in akun_lama:
            provider = o.get("provider", "-")
            country = o.get("country", "-")
            tag = o.get("tag", "")
            if (not provider or provider == "-") and tag:
                provider = parse_provider_from_tag(tag)
            if (not country or country == "-") and tag:
                country = get_country_code_from_tag(tag)
            o["provider"] = provider
            o["country"] = country
            filtered_lama.append(o)
            tag_lama.append(tag if tag else "VPN")
            provider_lama.append(provider)
            country_lama.append(country)
        configs_to_test = filtered_lama + akun_baru
        orig_tags = tag_lama + tag_baru
        orig_providers = provider_lama + provider_baru
        orig_countries = country_lama + country_baru

        logging.info(f"[main_callback] Akan dites total {len(configs_to_test)} node. {len(filtered_lama)} lama, {len(akun_baru)} baru.")
        for cfg in configs_to_test:
            logging.info(f"[main_callback] Node: {cfg.get('tag', '-')} path: {cfg.get('path', '-')}, transport.path: {cfg.get('transport', {}).get('path', '-')}")
        progress_state["file_name"] = file_name
        progress_state["base_config"] = base_config
        progress_state["final_config"] = {}

        start_batch_test(configs_to_test, orig_tags, orig_providers, orig_countries)
        return (
            html.Div([
                html.Div(f"Memulai test {len(configs_to_test)} node (hanya yang ada IP di path)..."),
                progress_bar(0, len(configs_to_test))
            ]),
            [],
            {},
            dash.no_update,
            None, None,
            False
        )

    if triggered == "progress-interval":
        prog = progress_state
        results = [r[1] for r in prog["results"] if isinstance(r, tuple) and r is not None and len(r) == 2]
        logging.debug(f"[main_callback:progress-interval] Jumlah hasil test: {len(results)}")
        stat_info = make_stat_and_rekom(results) if results else {}

        if not prog["running"]:
            final_nodes = []
            for i, (cfg, stat) in enumerate([r for r in prog["results"] if isinstance(r, tuple) and r is not None and len(r) == 2]):
                if not stat:
                    continue
                provider = stat.get('provider', '-')
                country = stat.get('country', '-')
                tag = stat.get('tag', '')
                if (not provider or provider == "-") and tag:
                    provider = parse_provider_from_tag(tag)
                if (not country or country == "-") and tag:
                    country = get_country_code_from_tag(tag)
                stat['provider'] = provider
                stat['country'] = country
                if provider.strip().upper() == "IL" or country.strip().upper() == "IL":
                    continue
                if stat['status'] == '✅ LIVE':
                    node = cfg.copy()
                    node["provider"] = provider
                    node["country"] = country
                    node["tag"] = tag
                    if "path" in node:
                        del node["path"]
                    final_nodes.append(node)

            def node_priority(node):
                tag = node.get("tag", "")
                if tag.startswith("🇮🇩"):
                    return (0, tag)
                elif tag.startswith("🇸🇬"):
                    return (1, tag)
                else:
                    return (2, tag)
            final_nodes_sorted = sorted(final_nodes, key=node_priority)
            final_nodes_sorted = format_and_clean_nodes(final_nodes_sorted)

            original_outbounds = prog["base_config"].get("outbounds", [])
            new_outbounds = []
            inserted = False
            for outbound in original_outbounds:
                new_outbounds.append(outbound)
            if not inserted:
                new_outbounds.extend(final_nodes_sorted)

            final_config = copy.deepcopy(prog["base_config"])
            final_config["outbounds"] = new_outbounds

            all_tags = [n["tag"] for n in final_nodes_sorted if n.get("tag")]
            for outbound in final_config.get("outbounds", []):
                if outbound.get("type") == "selector" and outbound.get("tag") == "Internet":
                    outbound["outbounds"] = ["Best Latency"] + all_tags + ["direct"]
                elif outbound.get("type") == "urltest" and outbound.get("tag") == "Best Latency":
                    outbound["outbounds"] = all_tags + ["direct"]
                elif outbound.get("type") == "selector" and outbound.get("tag") == "Lock Region ID":
                    outbound["outbounds"] = all_tags

            progress_state["final_config"] = final_config

            logging.info(f"[main_callback:progress-interval] Test selesai. {len(final_nodes_sorted)} node LIVE.")
            return (
                "",
                results,
                stat_info,
                dash.no_update, None, None,
                True
            )
        else:
            bar = progress_bar(prog["progress"], prog["total"])
            return (
                bar,
                results,
                stat_info,
                dash.no_update, None, None,
                False
            )

    if triggered == "download-btn":
        final_config = progress_state.get("final_config", {}) or progress_state.get("base_config", {})
        file_name = progress_state.get("file_name", "vpn_config.json")
        if final_config:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dict(
                content=json.dumps(final_config, indent=2, ensure_ascii=False),
                filename=file_name,
                type="application/json"
            ), None, True

    if triggered == "download-json-btn":
        json_results = progress_state.get("json_results", [])
        file_name = progress_state.get("file_name", "vpn_test_results.json").replace(".txt", "-test.json")
        if json_results:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, None, dict(
                content=json.dumps(json_results, indent=2, ensure_ascii=False),
                filename=file_name,
                type="application/json"
            ), True

    if triggered == "upload-btn":
        try:
            file_name = progress_state.get("file_name", "vpn_config.json")
            config_to_upload = progress_state.get("final_config", {}) or progress_state.get("base_config", {})
            if config_to_upload:
                converter.upload_to_github(config_to_upload, file_name, "update vpn config")
                return dash.no_update, dash.no_update, dash.no_update, html.Div(
                    f"Berhasil upload ke GitHub: {file_name}", style={"color": "green"}
                ), None, None, True
            else:
                return dash.no_update, dash.no_update, dash.no_update, html.Div(
                    "Tidak ada config yang diupload.", style={"color": "red"}
                ), None, None, True
        except Exception as e:
            logging.error(f"Upload gagal: {e}")
            return dash.no_update, dash.no_update, dash.no_update, html.Div(
                f"Upload gagal: {e}", style={"color": "red"}
            ), None, None, True

if __name__ == "__main__":
    app.run(debug=True)