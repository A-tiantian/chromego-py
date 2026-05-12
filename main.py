#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
import yaml
import json
import urllib.request
import logging
import geoip2.database
import os
import hashlib
import re
import base64
import socket
import time
from urllib.parse import urlparse, parse_qs, quote

# ==================== 全局设置 (原版保留) ====================
socket.setdefaulttimeout(15)
urllib.request.socket.setdefaulttimeout(15)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("ChromeGo")

servers_list: list[str] = []
extracted_proxies: list[dict] = []

geo_reader = None
try:
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except Exception:
    logger.warning("GeoLite2-City.mmdb 未找到，位置信息将显示 UNK")

def get_location(ip: str) -> str:
    if not geo_reader or not ip:
        return "UNK"
    try:
        resp = geo_reader.city(str(ip).strip('[]'))
        c = resp.country.iso_code or "UNK"
        city = resp.city.name or ""
        return f"{c}-{city}" if city else c
    except:
        return "UNK"

# ==================== 新增：国家代码转国旗图标 ====================
def get_flag(country_code: str) -> str:
    """将国家代码转换为国旗emoji"""
    if not country_code or country_code in ("UNK", "??"):
        return "🌐"
    try:
        # 取前两个字母并转为国旗emoji
        code = str(country_code).upper()[:2]
        if len(code) != 2:
            return "🌐"
        return ''.join(chr(ord(c) + 127397) for c in code)
    except:
        return "🌐"

# ==================== 名称生成函数（统一使用图标） ====================
def get_node_name(server: str, node_type: str, index: int, suffix: str = "") -> str:
    loc = get_location(server)
    # 分离国家代码和城市
    if '-' in loc:
        country_code, city = loc.split('-', 1)
    else:
        country_code = loc
        city = ""
    
    flag = get_flag(country_code)
    base_name = f"{flag} {country_code}"
    if city:
        base_name += f"-{city}"
    
    return f"{base_name}-{node_type.upper()}-{index}{suffix}"

def make_fingerprint(p: dict) -> str:
    key = f"{p.get('server','')}|{p.get('port','')}|{p.get('type','')}|" \
          f"{p.get('uuid') or p.get('password') or p.get('auth-str','')}|" \
          f"{p.get('network','')}|{p.get('sni','')}|{p.get('servername','')}"
    return hashlib.md5(key.lower().encode()).hexdigest()

def preprocess_subscription(data: str) -> str:
    content = data.strip()
    if not content:
        return content
    try:
        padding = '=' * (-len(content) % 4)
        decoded = base64.b64decode(content + padding, validate=False).decode('utf-8', errors='ignore')
        if any(decoded.startswith(prefix) for prefix in ('vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://')):
            return decoded
    except:
        pass
    return content

# ==================== 修正后的 URI 转换逻辑 ====================
def to_nekobox_uri(p: dict) -> str:
    try:
        t = p.get('type', '').lower()
        name = quote(str(p.get('name', 'node')))
        server = str(p.get('server', ''))
        
        if ":" in server and not server.startswith("["):
            server = f"[{server}]"
            
        port = p.get('port')
        if not server or not port: 
            return ""

        if t == 'vless':
            uuid = p.get('uuid')
            net = p.get('network', 'tcp')
            uri = f"vless://{uuid}@{server}:{port}?encryption=none&type={net}"
            
            ropts = p.get('reality-opts', {})
            if ropts:
                uri += f"&security=reality&sni={p.get('sni','')}&pbk={ropts.get('public-key','')}&sid={ropts.get('short-id','')}"
            elif p.get('tls'):
                uri += f"&security=tls&sni={p.get('sni','')}"
            else:
                uri += "&security=none"
            
            wsopts = p.get('ws-opts', {})
            if net == 'ws':
                uri += f"&path={quote(wsopts.get('path','/'))}"
            return f"{uri}#{name}"
        
        elif t in ['hysteria2', 'hy2']:
            password = p.get('password') or p.get('auth-str', '') or p.get('auth', '')
            sni = p.get('sni') or p.get('tls', {}).get('sni') or p.get('server_name', '') or ''
            
            auth_part = f"{quote(str(password))}@" if password else ""
            
            params = [f"insecure={'1' if p.get('skip-cert-verify', True) else '0'}"]
            if sni:
                params.append(f"sni={quote(sni)}")
            
            uri = f"hy2://{auth_part}{server}:{port}?{'&'.join(params)}"
            return f"{uri}#{name}"
        
        elif t == 'tuic':
            uuid = p.get('uuid', '')
            pw = p.get('password', '')
            sni = p.get('sni', '')
            return f"tuic://{uuid}:{pw}@{server}:{port}?sni={sni}&alpn=h3&allow_insecure=1&congestion_control=bbr&udp_relay_mode=native#{name}"
            
        elif t == 'naive':
            return f"naive+https://{p.get('username')}:{p.get('password')}@{server}:{port}#{name}"
            
        elif t == 'hysteria':
            auth = p.get('auth-str') or p.get('password') or ''
            sni = p.get('sni') or p.get('peer') or ''
            alpn_list = p.get('alpn', ['h3'])
            alpn = ",".join(alpn_list) if isinstance(alpn_list, list) else alpn_list
            up = str(p.get('up', '11')).split(' ')[0]
            down = str(p.get('down', '55')).split(' ')[0]
            
            uri = f"hysteria://{server}:{port}?upmbps={up}&downmbps={down}&auth={auth}&insecure=1&peer={sni}&alpn={alpn}"
            return f"{uri}#{name}"
            
        return ""
    except Exception as e:
        logger.warning(f"URI 生成失败: {e}")
        return ""

# ==================== 原始提取逻辑 ====================

def parse_vless_link(link: str) -> dict | None:
    try:
        if not link.startswith('vless://'): return None
        url = urlparse(link)
        uuid = url.username
        server = url.hostname
        port = int(url.port) if url.port else 443
        params = parse_qs(url.query)

        p = {
            "name": f"{get_location(server)}-VLESS-{len(extracted_proxies)+1}",
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "network": params.get('type', ['tcp'])[0],
            "tls": params.get('security', ['none'])[0] in ('tls', 'reality'),
            "sni": params.get('sni', [''])[0] or params.get('serverName', [''])[0],
            "flow": params.get('flow', [''])[0],
            "client-fingerprint": params.get('fp', ['chrome'])[0],
        }
        if params.get('security', [''])[0] == 'reality':
            p['reality-opts'] = {
                "public-key": params.get('pbk', [''])[0],
                "short-id": params.get('sid', [''])[0]
            }
        return {k: v for k, v in p.items() if v not in (None, '', {}, [])}
    except:
        return None

def process_file(file_path: str):
    if not os.path.exists(file_path):
        logger.warning(f"跳过不存在的文件: {file_path}")
        return
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    raw_data = resp.read().decode('utf-8', errors='ignore')
                processed_data = preprocess_subscription(raw_data)
                lines = [line.strip() for line in processed_data.splitlines() if line.strip()]
                for line in lines:
                    if line.startswith('vless://'):
                        proxy = parse_vless_link(line)
                        if proxy:
                            fp = make_fingerprint(proxy)
                            if fp not in servers_list:
                                extracted_proxies.append(proxy)
                                servers_list.append(fp)
                if url.endswith(('.yaml', '.yml')) or 'proxies:' in processed_data or 'proxy:' in processed_data:
                    process_clash(processed_data)
                else:
                    process_json(processed_data)
                logger.info(f"✓ 订阅源处理完成: {url}")
            except Exception as e:
                logger.error(f"✗ 处理失败 {url}: {type(e).__name__}")
    except Exception as e:
        logger.error(f"读取 {file_path} 失败: {e}")

def process_clash(data: str):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', []) or content.get('proxy', [])
        for i, p in enumerate(proxies):
            if not isinstance(p, dict) or not p.get('server'): continue
            p = dict(p)
            fp = make_fingerprint(p)
            if fp in servers_list: continue
            original_name = p.get('name', '')
            if original_name.startswith('Y-'):
                new_name = original_name[2:]
            else:
                new_name = get_node_name(p.get('server'), p.get('type', 'unk'), len(extracted_proxies)+1)
            p['name'] = new_name
            extracted_proxies.append(p)
            servers_list.append(fp)
    except Exception as e:
        logger.error(f"Clash 处理异常: {e}")

def process_json(data: str):
    try:
        content = json.loads(data)
        if 'server' in content or 'servers' in content:
            servers = content.get('server') or content.get('servers', [])
            if isinstance(servers, str): servers = [servers]
            has_hop = any(',' in str(s) and '-' in str(s) for s in servers)
            typ = "hysteria2" if has_hop or "hysteria2" in str(content).lower() else "hysteria"
            for i, s in enumerate(servers):
                if not s: continue
                server, main_port, ports_range = parse_server_port(s)
                name_suffix = f" ({ports_range})" if ports_range else ""
                if typ == "hysteria":
                    alpn = content.get('alpn')
                    if isinstance(alpn, str): alpn = [alpn]
                    elif not alpn: alpn = ["h3"]
                    p = {
                        "name": get_node_name(server, typ, len(extracted_proxies)+1, name_suffix),
                        "type": typ, "server": server, "port": main_port,
                        "password": content.get('auth') or content.get('password', content.get('auth_str', '')),
                        "auth-str": content.get('auth_str') or content.get('auth') or content.get('password', ''),
                        "sni": content.get('sni') or content.get('peer') or content.get('server_name', ''),
                        "skip-cert-verify": content.get('insecure', True), "alpn": alpn,
                        "up": content.get('upmbps') or content.get('up') or 11,
                        "down": content.get('downmbps') or content.get('down') or 55,
                    }
                else:
                    tls = content.get('tls', {})
                    p = {
                        "name": get_node_name(server, typ, len(extracted_proxies)+1, name_suffix),
                        "type": typ, 
                        "server": server, 
                        "port": main_port,
                        "password": content.get('auth') or content.get('password', content.get('auth_str', '')),
                        "auth-str": content.get('auth_str') or content.get('auth') or content.get('password', ''),
                        "sni": tls.get('sni') or content.get('sni') or content.get('peer') or content.get('server_name', ''),
                        "skip-cert-verify": tls.get('insecure', content.get('insecure', True)), 
                        "alpn": content.get('alpn', ["h3"]),
                    }
                if ports_range: p['ports'] = ports_range
                fp = make_fingerprint(p)
                if fp not in servers_list:
                    extracted_proxies.append(p)
                    servers_list.append(fp)

        outbounds = content.get('outbounds', [])
        if not outbounds and 'config' in content:
            outbounds = content['config'].get('outbounds', [])

        for ob in outbounds:
            if not isinstance(ob, dict): continue
            proto = (ob.get('protocol') or ob.get('type') or '').lower()
            if proto in ('direct', 'dns', 'freedom'): continue
            p = {"name": "", "type": proto}
            settings = ob.get('settings', {})
            stream = ob.get('streamSettings', {}) or ob.get('transport', {})
            if proto == 'vless':
                vnext = settings.get('vnext', [{}])[0]
                if not vnext: continue
                user = vnext.get('users', [{}])[0]
                server = vnext.get('address')
                p.update({
                    "server": server, "port": int(vnext.get('port', 443)),
                    "uuid": user.get('id'), "flow": user.get('flow', ''),
                    "network": stream.get('network', 'tcp'),
                    "tls": stream.get('security') in ('tls', 'reality', 'xtls'),
                    "udp": True
                })
                tls_data = stream.get('realitySettings', {}) or stream.get('tlsSettings', {})
                if tls_data:
                    p["sni"] = tls_data.get('serverName', '')
                    p["client-fingerprint"] = tls_data.get('fingerprint', 'chrome')
                    if stream.get('security') == 'reality':
                        p["reality-opts"] = {"public-key": tls_data.get('publicKey', ''), "short-id": tls_data.get('shortId', '')}
                if stream.get('network') == 'ws':
                    ws = stream.get('wsSettings', {})
                    p["ws-opts"] = {"path": ws.get('path', '/'), "headers": ws.get('headers', {})}
            elif proto == 'naive':
                p.update({
                    "server": ob.get('server') or settings.get('address'),
                    "port": int(ob.get('port') or settings.get('port', 443)),
                    "username": ob.get('username') or settings.get('username', ''),
                    "password": ob.get('password') or settings.get('password', '')
                })
            elif proto == 'tuic':
                p.update({
                    "server": ob.get('server') or settings.get('address'),
                    "port": int(ob.get('port') or settings.get('port', 443)),
                    "uuid": settings.get('uuid') or settings.get('user_id', ''),
                    "password": settings.get('password', ''),
                    "sni": ob.get('sni') or settings.get('sni', ''),
                    "alpn": ["h3"]
                })
            if p.get('server'):
                p['name'] = get_node_name(p['server'], proto, len(extracted_proxies)+1)
                fp = make_fingerprint(p)
                if fp not in servers_list:
                    extracted_proxies.append(p)
                    servers_list.append(fp)

        if 'proxy' in content and isinstance(content['proxy'], str) and content['proxy'].startswith('https://'):
            res = urlparse(content['proxy'])
            p = {
                "name": get_node_name(res.hostname, "NAIVE", len(extracted_proxies)+1),
                "type": "naive", "server": res.hostname, "port": res.port or 443,
                "username": res.username, "password": res.password
            }
            fp = make_fingerprint(p)
            if fp not in servers_list:
                extracted_proxies.append(p)
                servers_list.append(fp)
    except Exception as e:
        logger.error(f"JSON 处理异常: {e}")

def parse_server_port(srv):
    srv = str(srv).strip()
    ports_range = None
    if ',' in srv:
        parts = [p.strip() for p in srv.split(',')]
        main_part = parts[0]
        if len(parts) > 1 and '-' in parts[-1]:
            ports_range = parts[-1]
        srv = main_part
    if srv.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+)', srv)
        if m: return m.group(1), int(m.group(2)), ports_range
    if ':' in srv:
        parts = srv.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1]), ports_range
    return srv, 443, ports_range

# ====================== 主程序逻辑 ======================
if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    os.makedirs("urls", exist_ok=True)
    logger.info("=== ChromeGo Enhanced 优化版启动 ===")
    
    for file_path in ["urls/sources.txt", "urls/extra_sources.txt"]:
        process_file(file_path)
    
    clash_proxies = []
    for p in extracted_proxies:
        temp_p = p.copy()
        if temp_p.get('type') == 'naive':
            temp_p['type'] = 'http'
            temp_p['tls'] = True
        clash_proxies.append(temp_p)

    with open("outputs/clash_meta.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)
    
    uri_list = [to_nekobox_uri(p) for p in extracted_proxies if to_nekobox_uri(p)]
    
    with open("outputs/sub_raw.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(uri_list))
    
    b64_str = base64.b64encode("\n".join(uri_list).encode()).decode()
    with open("outputs/sub_base64.txt", "w", encoding="utf-8") as f:
        f.write(b64_str)

    logger.info(f"✅ 处理完毕！总提取: {len(extracted_proxies)}，有效转换 URI: {len(uri_list)}")
