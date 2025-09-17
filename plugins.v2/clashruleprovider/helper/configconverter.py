import base64
import binascii
import json

from typing import List, Dict, Any, Optional, Union
from urllib.parse import urlparse, parse_qs, unquote, parse_qsl, quote

from app.utils.string import StringUtils


class Converter:
    """
    Converter for V2Ray Subscription

    Reference:
    https://github.com/MetaCubeX/mihomo/blob/Alpha/common/convert/converter.go
    https://github.com/SubConv/SubConv/blob/main/modules/convert/converter.py
    """
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome'

    @staticmethod
    def decode_base64(data):
        # 添加适配不同 padding 的容错机制
        data = data.strip()
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data)

    @staticmethod
    def decode_base64_urlsafe(data):
        data = data.strip()
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def try_decode_base64_json(data):
        try:
            return json.loads(Converter.decode_base64(data).decode('utf-8'))
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, TypeError):
            return None

    @staticmethod
    def unique_name(name_map: Dict[str, int], name: str) -> str:
        index = name_map.get(name, 0)
        name_map[name] = index + 1
        if index > 0:
            return f"{name}-{index:02d}"
        return name

    @staticmethod
    def lower_string(string: Optional[str]) -> Optional[str]:
        if isinstance(string, str):
            return string.lower()
        return string

    @staticmethod
    def handle_vshare_link(link: str, names: Dict[str, int]) -> Optional[Dict[str, Any]]:
        try:
            url_info = urlparse(link)
            query = dict(parse_qsl(url_info.query))
            scheme = url_info.scheme.lower()

            if not url_info.hostname or not url_info.port:
                return None

            proxy: Dict[str, Any] = {
                'name': Converter.unique_name(names, unquote(url_info.fragment or f"{url_info.hostname}:{url_info.port}")),
                'type': scheme,
                'server': url_info.hostname,
                'port': url_info.port,
                'uuid': url_info.username,
                'udp': True
            }

            # TLS and Reality settings
            tls_mode = Converter.lower_string(query.get('security'))
            if tls_mode in ['tls', 'reality']:
                proxy['tls'] = True
                proxy['client-fingerprint'] = query.get('fp', 'chrome')
                if 'alpn' in query:
                    proxy['alpn'] = query['alpn'].split(',')
                if 'sni' in query:
                    proxy['servername'] = query['sni']

                if tls_mode == 'reality':
                    proxy['reality-opts'] = {
                        'public-key': query.get('pbk'),
                        'short-id': query.get('sid')
                    }

            # Network settings
            network = Converter.lower_string(query.get('type', 'tcp'))
            header_type = Converter.lower_string(query.get('headerType'))

            if header_type == 'http':
                network = 'http'
            elif network == 'http':
                network = 'h2'

            proxy['network'] = network

            if network == 'tcp' and header_type == 'http':
                proxy['http-opts'] = {
                    'method': query.get('method', 'GET'),
                    'path': [query.get('path', '/')],
                    'headers': {'Host': [query.get('host', url_info.hostname)]}
                }
            elif network == 'h2':
                 proxy["h2-opts"] = {
                    "path": query.get("path", "/"),
                    "host": [query.get("host", url_info.hostname)]
                }
            elif network in ['ws', 'httpupgrade']:
                ws_opts: Dict[str, Any] = {
                    'path': query.get('path', '/'),
                    'headers': {
                        'Host': query.get('host', url_info.hostname),
                        'User-Agent': Converter.user_agent
                    }
                }
                if 'ed' in query:
                    try:
                        med = int(query['ed'])
                        if network == 'ws':
                            ws_opts['max-early-data'] = med
                            ws_opts['early-data-header-name'] = query.get('eh', 'Sec-WebSocket-Protocol')
                        elif network == 'httpupgrade':
                             ws_opts['v2ray-http-upgrade-fast-open'] = True
                    except (ValueError, TypeError):
                        pass
                proxy['ws-opts'] = ws_opts
            elif network == 'grpc':
                proxy['grpc-opts'] = {
                    'grpc-service-name': query.get('serviceName', '')
                }
            
            # Packet Encoding
            packet_encoding = Converter.lower_string(query.get('packetEncoding'))
            if packet_encoding == 'packet':
                proxy['packet-addr'] = True
            elif packet_encoding != 'none':
                proxy['xudp'] = True

            # Encryption
            if 'encryption' in query and query['encryption']:
                proxy['encryption'] = query['encryption']

            if 'flow' in query:
                proxy['flow'] = query['flow']

            return proxy
        except Exception:
            return None

    @staticmethod
    def convert_line(line: str, names: Optional[Dict[str, int]] = None, skip_exception: bool = True
                     ) -> Optional[Dict[str, Any]]:
        if names is None:
            names = {}
        proxy: Optional[Dict[str, Any]] = None
        if "://" in line:
            scheme, body = line.split("://", 1)
            scheme = scheme.lower()
            if scheme == "vmess":
                try:
                    vmess_data = Converter.try_decode_base64_json(body)
                    # Xray VMessAEAD share link
                    if vmess_data is None:
                        proxy = Converter.handle_vshare_link(line, names)
                        return proxy
                    name = Converter.unique_name(names, vmess_data.get("ps", "vmess"))
                    net = Converter.lower_string(vmess_data.get("net"))
                    fake_type = Converter.lower_string(vmess_data.get("type"))
                    tls_mode = Converter.lower_string(vmess_data.get("tls"))
                    cipher = vmess_data.get("scy", "auto") or "auto"
                    alter_id = vmess_data.get("aid", 0)

                    # 调整 network 类型
                    if fake_type == "http":
                        net = "http"
                    elif net == "http":
                        net = "h2"

                    proxy = {
                        "name": name,
                        "type": "vmess",
                        "server": vmess_data.get("add"),
                        "port": vmess_data.get("port"),
                        "uuid": vmess_data.get("id"),
                        "alterId": alter_id,
                        "cipher": cipher,
                        "tls": tls_mode.endswith("tls") or tls_mode == "reality",
                        "udp": True,
                        "xudp": True,
                        "skip-cert-verify": False,
                        "network": net
                    }

                    # TLS Reality 扩展
                    if proxy["tls"]:
                        proxy["client-fingerprint"] = vmess_data.get("fp", "chrome") or "chrome"
                        alpn = vmess_data.get("alpn")
                        if alpn:
                            proxy["alpn"] = alpn.split(",") if isinstance(alpn, str) else alpn
                        sni = vmess_data.get("sni")
                        if sni:
                            proxy["servername"] = sni

                        if tls_mode == "reality":
                            proxy["reality-opts"] = {
                                "public-key": vmess_data.get("pbk"),
                                "short-id": vmess_data.get("sid")
                            }

                    path = vmess_data.get("path", "/")
                    host = vmess_data.get("host")

                    # 不同 network 的扩展字段处理
                    if net == "tcp":
                        if fake_type == "http":
                            proxy["http-opts"] = {
                                "path": path,
                                "headers": {"Host": host} if host else {}
                            }
                    elif net == "http":
                        headers = {}
                        if host:
                            headers["Host"] = [host]
                        proxy["http-opts"] = {"path": [path], "headers": headers}

                    elif net == "h2":
                        proxy["h2-opts"] = {
                            "path": path,
                            "host": [host] if host else []
                        }

                    elif net == "ws":
                        ws_headers = {"Host": host} if host else {}
                        ws_headers["User-Agent"] = Converter.user_agent
                        ws_opts = {
                            "path": path,
                            "headers": ws_headers
                        }
                        # 补充 early-data 配置
                        early_data = vmess_data.get("ed")
                        if early_data:
                            try:
                                ws_opts["max-early-data"] = int(early_data)
                            except ValueError:
                                pass
                        early_data_header = vmess_data.get("edh")
                        if early_data_header:
                            ws_opts["early-data-header-name"] = early_data_header
                        proxy["ws-opts"] = ws_opts

                    elif net == "grpc":
                        proxy["grpc-opts"] = {
                            "grpc-service-name": path
                        }
                except Exception as e:
                    if not skip_exception:
                        raise ValueError(f"VMESS parse error: {e}") from e

            elif scheme == "vless":
                try:
                    proxy = Converter.handle_vshare_link(line, names)
                except Exception as e:
                    if not skip_exception:
                        raise ValueError(f"VLESS parse error: {e}") from e

            elif scheme == "trojan":
                try:
                    parsed = urlparse(line)
                    query = dict(parse_qsl(parsed.query))

                    name = Converter.unique_name(names, unquote(parsed.fragment or f"{parsed.hostname}:{parsed.port}"))

                    trojan: Dict[str, Any] = {
                        "name": name,
                        "type": "trojan",
                        "server": parsed.hostname,
                        "port": parsed.port or 443,
                        "password": parsed.username or "",
                        "udp": True,
                        "tls": True
                    }

                    # skip-cert-verify
                    try:
                        trojan["skip-cert-verify"] = StringUtils.to_bool(query.get("allowInsecure", "0"))
                    except ValueError:
                        trojan["skip-cert-verify"] = False

                    # optional fields
                    if "sni" in query:
                        trojan["sni"] = query["sni"]

                    alpn = query.get("alpn")
                    if alpn:
                        trojan["alpn"] = alpn.split(",")

                    network = query.get("type", "").lower()
                    if network:
                        trojan["network"] = network

                    if network == "ws":
                        headers = {"User-Agent": Converter.user_agent}
                        trojan["ws-opts"] = {
                            "path": query.get("path", "/"),
                            "headers": headers
                        }

                    elif network == "grpc":
                        trojan["grpc-opts"] = {
                            "grpc-service-name": query.get("serviceName")
                        }

                    fp = query.get("fp")
                    trojan["client-fingerprint"] = fp if fp else "chrome"
                    proxy = trojan

                except Exception as e:
                    if not skip_exception:
                        raise ValueError(f"Trojan parse error: {e}") from e

            elif scheme in ("socks", "socks5", "socks5h", "http", "https"):
                try:
                    parsed = urlparse(line)
                    server = parsed.hostname
                    port = parsed.port
                    name = Converter.unique_name(names, unquote(parsed.fragment or f"{server}:{port}"))

                    username = ""
                    password = ""
                    if parsed.username:
                        try:
                            # The userinfo part might be base64 encoded
                            decoded_userinfo = Converter.decode_base64(parsed.username.encode('utf-8')).decode('utf-8')
                            if ":" in decoded_userinfo:
                                username, password = decoded_userinfo.split(":", 1)
                            else:
                                username = decoded_userinfo
                        except (binascii.Error, UnicodeDecodeError):
                            # If not base64 encoded, use directly
                            username = parsed.username
                            password = parsed.password if parsed.password else ""

                    proxy_type = ""
                    if scheme in ("socks", "socks5", "socks5h"):
                        proxy_type = "socks5"
                    elif scheme in ("http", "https"):
                        proxy_type = "http"

                    proxy = {
                        "name": name,
                        "type": proxy_type,
                        "server": server,
                        "port": port,
                        "username": username,
                        "password": password,
                        "skip-cert-verify": True
                    }

                    if scheme == "https":
                        proxy["tls"] = True

                except Exception as e:
                    if not skip_exception:
                        raise ValueError(f"SOCKS/HTTP parse error: {e}") from e

            elif scheme == "ss":
                try:
                    parsed = urlparse(line)

                    if parsed.port is None and parsed.netloc:
                        base64_body = parsed.netloc
                        decoded_body = Converter.decode_base64_urlsafe(base64_body).decode('utf-8')

                        new_line = f"ss://{decoded_body}"
                        if parsed.fragment:
                            new_line += f"#{parsed.fragment}"
                        parsed = urlparse(new_line)

                    name = Converter.unique_name(names, unquote(parsed.fragment or f"{parsed.hostname}:{parsed.port}"))

                    cipher_raw = parsed.username
                    password = parsed.password
                    cipher = cipher_raw

                    if not password and cipher_raw:
                        try:
                            decoded_user = Converter.decode_base64_urlsafe(cipher_raw).decode('utf-8')
                        except (binascii.Error, UnicodeDecodeError):
                            decoded_user = Converter.decode_base64(cipher_raw).decode('utf-8')

                        if ":" in decoded_user:
                            cipher, password = decoded_user.split(":", 1)
                        else:
                            cipher = decoded_user

                    server = parsed.hostname
                    port = parsed.port
                    query = dict(parse_qsl(parsed.query))
                    proxy = {
                        "name": name,
                        "type": "ss",
                        "server": server,
                        "port": port,
                        "cipher": cipher,
                        "password": password,
                        "udp": True
                    }
                    if query.get("udp-over-tcp") == "true" or query.get("uot") == "1":
                        proxy["udp-over-tcp"] = True
                    plugin = query.get("plugin")
                    if plugin and ";" in plugin:
                        query_string = "pluginName=" + plugin.replace(";", "&")
                        plugin_info = dict(parse_qsl(query_string))
                        plugin_name = plugin_info.get("pluginName", "")

                        if "obfs" in plugin_name:
                            proxy["plugin"] = "obfs"
                            proxy["plugin-opts"] = {
                                "mode": plugin_info.get("obfs"),
                                "host": plugin_info.get("obfs-host"),
                            }
                        elif "v2ray-plugin" in plugin_name:
                            proxy["plugin"] = "v2ray-plugin"
                            proxy["plugin-opts"] = {
                                "mode": plugin_info.get("mode"),
                                "host": plugin_info.get("host"),
                                "path": plugin_info.get("path"),
                                "tls": "tls" in plugin,
                            }

                except Exception as e:
                    if not skip_exception:
                        raise ValueError(f"SS parse error: {e}") from e

            elif scheme == "ssr":
                try:
                    try:
                        decoded_body = Converter.decode_base64_urlsafe(body).decode('utf-8')
                    except (binascii.Error, UnicodeDecodeError):
                        decoded_body = Converter.decode_base64(body).decode('utf-8')

                    parts, _, params_str = decoded_body.partition("/?")

                    part_list = parts.split(":", 5)
                    if len(part_list) != 6:
                        raise ValueError("Invalid SSR link format: incorrect number of parts")

                    host, port_str, protocol, method, obfs, password_enc = part_list

                    try:
                        port = int(port_str)
                    except ValueError:
                        raise ValueError("Invalid port in SSR link")

                    password = Converter.decode_base64_urlsafe(password_enc).decode('utf-8')
                    params = dict(parse_qsl(params_str))
                    remarks_b64 = params.get("remarks", "")
                    remarks = Converter.decode_base64_urlsafe(remarks_b64).decode('utf-8') if remarks_b64 else ""

                    obfsparam_b64 = params.get("obfsparam", "")
                    obfsparam = Converter.decode_base64_urlsafe(obfsparam_b64).decode(
                        'utf-8') if obfsparam_b64 else ""

                    protoparam_b64 = params.get("protoparam", "")
                    protoparam = Converter.decode_base64_urlsafe(protoparam_b64).decode(
                        'utf-8') if protoparam_b64 else ""

                    name = Converter.unique_name(names, remarks or f"{host}:{port}")

                    proxy = {
                        "name": name,
                        "type": "ssr",
                        "server": host,
                        "port": port,
                        "cipher": method,
                        "password": password,
                        "obfs": obfs,
                        "protocol": protocol,
                        "udp": True
                    }

                    if obfsparam:
                        proxy["obfs-param"] = obfsparam
                    if protoparam:
                        proxy["protocol-param"] = protoparam

                except Exception as e:
                    if not skip_exception:
                        raise ValueError(f"SSR parse error: {e}") from e

            elif scheme == "tuic":
                try:
                    parsed = urlparse(line)
                    query = dict(parse_qsl(parsed.query))

                    user = parsed.username
                    password = parsed.password
                    server = parsed.hostname
                    port = parsed.port

                    name = Converter.unique_name(names, unquote(parsed.fragment or f"{server}:{port}"))
                    proxy = {
                        "name": name,
                        "type": "tuic",
                        "server": server,
                        "port": port,
                        "udp": True
                    }

                    if password:
                        proxy["uuid"] = user
                        proxy["password"] = password
                    else:
                        proxy["token"] = user

                    if "congestion_control" in query:
                        proxy["congestion-controller"] = query["congestion_control"]
                    if "alpn" in query:
                        proxy["alpn"] = query["alpn"].split(",")
                    if "sni" in query:
                        proxy["sni"] = query["sni"]
                    if query.get("disable_sni", "0") == "1":
                        proxy["disable-sni"] = True
                    if "udp_relay_mode" in query:
                        proxy["udp-relay-mode"] = query["udp_relay_mode"]

                except Exception as e:
                    if not skip_exception:
                        raise ValueError(f"TUIC parse error: {e}") from e

            elif scheme == "anytls":
                try:
                    parsed = urlparse(line)
                    query = dict(parse_qsl(parsed.query))

                    username = parsed.username
                    password = parsed.password or username
                    server = parsed.hostname
                    port = parsed.port
                    insecure = query.get("insecure", "0") == "1"
                    sni = query.get("sni")
                    fingerprint = query.get("hpkp")

                    name = Converter.unique_name(names, unquote(parsed.fragment or f"{server}:{port}"))
                    proxy = {
                        "name": name,
                        "type": "anytls",
                        "server": server,
                        "port": port,
                        "username": username,
                        "password": password,
                        "sni": sni,
                        "fingerprint": fingerprint,
                        "skip-cert-verify": insecure,
                        "udp": True
                    }

                except Exception as e:
                    if not skip_exception:
                        raise ValueError(f"AnyTLS parse error: {e}") from e

            elif scheme == "hysteria":
                try:
                    parsed = urlparse(line)
                    query = dict(parse_qsl(parsed.query))

                    name = Converter.unique_name(names, unquote(parsed.fragment or f"{parsed.hostname}:{parsed.port}"))
                    hysteria: Dict[str, Any] = {
                        "name": name,
                        "type": "hysteria",
                        "server": parsed.hostname,
                        "port": parsed.port,
                    }

                    auth_str = query.get("auth")
                    if auth_str:
                        hysteria["auth_str"] = auth_str
                    obfs = query.get("obfs")
                    if obfs:
                        hysteria["obfs"] = obfs
                    sni = query.get("peer")
                    if sni:
                        hysteria["sni"] = sni
                    protocol = query.get("protocol")
                    if protocol:
                        hysteria["protocol"] = protocol
                    up = query.get("up")
                    if not up:
                        up = query.get("upmbps")
                    if up:
                        hysteria["up"] = up
                    down = query.get("down")
                    if not down:
                        down = query.get("downmbps")
                    if down:
                        hysteria["down"] = down
                    alpn = query.get("alpn", "")
                    if alpn:
                        hysteria["alpn"] = alpn.split(",")

                    # skip-cert-verify
                    insecure_str = query.get("insecure", "false")
                    try:
                        skip_cert_verify = StringUtils.to_bool(insecure_str)
                        if skip_cert_verify:
                            hysteria["skip-cert-verify"] = skip_cert_verify
                    except ValueError:
                        pass
                    proxy = hysteria

                except Exception as e:
                    if not skip_exception:
                        raise ValueError(f"Hysteria parse error: {e}") from e

            elif scheme in ("hysteria2", "hy2"):
                try:
                    parsed = urlparse(line)
                    query = dict(parse_qsl(parsed.query))

                    user_info = ""
                    if parsed.username:
                        if parsed.password:
                            user_info = f"{parsed.username}:{parsed.password}"
                        else:
                            user_info = parsed.username
                    password = user_info

                    server = parsed.hostname
                    port = parsed.port or 443
                    name = Converter.unique_name(names, unquote(parsed.fragment or f"{server}:{port}"))
                    proxy = {
                        "name": name,
                        "type": "hysteria2",
                        "server": server,
                        "port": port,
                        "password": password,
                        "obfs": query.get("obfs"),
                        "obfs-password": query.get("obfs-password"),
                        "sni": query.get("sni"),
                        "skip-cert-verify": StringUtils.to_bool(query.get("insecure", "false")),
                        "down": query.get("down"),
                        "up": query.get("up"),
                    }
                    if "pinSHA256" in query:
                        proxy["fingerprint"] = query.get("pinSHA256")
                    if "alpn" in query:
                        proxy["alpn"] = query["alpn"].split(",")

                except Exception as e:
                    if not skip_exception:
                        raise ValueError(f"Hysteria2 parse error: {e}") from e
        return proxy

    @staticmethod
    def convert_v2ray(v2ray_link: Union[list, bytes], skip_exception: bool = True) -> List[Dict[str, Any]]:
        if isinstance(v2ray_link, bytes):
            decoded = Converter.decode_base64(v2ray_link).decode("utf-8")
            lines = decoded.strip().splitlines()
        else:
            lines = v2ray_link
        proxies = []
        names = {}
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if "://" not in line:
                continue
            proxy = Converter.convert_line(line, names, skip_exception=skip_exception)
            if not proxy:
                if not skip_exception:
                    raise ValueError("convert v2ray subscribe error: format invalid")
            proxies.append(proxy)
        return proxies

    @staticmethod
    def convert_to_share_link(proxy_config: Dict[str, Any]) -> Optional[str]:
        proxy_type = proxy_config.get("type")
        name = proxy_config.get("name", "proxy")

        if proxy_type == "vmess":
            vmess_config = {
                "v": "2",
                "ps": name,
                "add": proxy_config.get("server", ""),
                "port": str(proxy_config.get("port", "")),
                "id": proxy_config.get("uuid", ""),
                "aid": str(proxy_config.get("alterId", 0)),
                "scy": proxy_config.get("cipher", "auto"),
                "net": proxy_config.get("network", "tcp"),
                "type": "none",
                "tls": "tls" if proxy_config.get("tls") else "",
                "host": "",
                "path": "/",
            }

            if proxy_config.get("network") == "http":
                vmess_config["type"] = "http"

            network = proxy_config.get("network")
            if network == "ws":
                ws_opts = proxy_config.get("ws-opts", {})
                vmess_config["host"] = ws_opts.get("headers", {}).get("Host", "")
                vmess_config["path"] = ws_opts.get("path", "/")
            elif network == "http":
                http_opts = proxy_config.get("http-opts", {})
                vmess_config["host"] = http_opts.get("headers", {}).get("Host", "")
                vmess_config["path"] = http_opts.get("path", "/")
            elif network == "h2":
                h2_opts = proxy_config.get("h2-opts", {})
                vmess_config["host"] = h2_opts.get("host")[0] if h2_opts.get("host") else ""
                vmess_config["path"] = h2_opts.get("path", "/")
            # Remove empty values to keep the JSON clean
            vmess_config = {k: v for k, v in vmess_config.items() if v not in ["", None]}
            encoded_str = base64.b64encode(json.dumps(vmess_config).encode("utf-8")).decode("utf-8")
            return f"vmess://{encoded_str}"

        elif proxy_type == "ss":
            method = proxy_config.get("cipher")
            password = proxy_config.get("password")
            server = proxy_config.get("server")
            port = proxy_config.get("port")
            if not all([method, password, server, port]):
                return None
            credentials = f"{method}:{password}@{server}:{port}"
            encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
            return f"ss://{encoded_credentials}#{quote(name)}"

        elif proxy_type == "trojan":
            password = proxy_config.get("password")
            server = proxy_config.get("server")
            port = proxy_config.get("port")
            if not all([password, server, port]):
                return None

            query_params = {}
            if proxy_config.get("sni"):
                query_params["sni"] = proxy_config["sni"]
            if proxy_config.get("alpn"):
                query_params["alpn"] = ",".join(proxy_config["alpn"])
            if proxy_config.get("skip-cert-verify"):
                query_params["allowInsecure"] = "1"

            network = proxy_config.get("network")
            if network:
                query_params["type"] = network
                if network == "ws":
                    ws_opts = proxy_config.get("ws-opts", {})
                    path = ws_opts.get("path", "/")
                    host = ws_opts.get("headers", {}).get("Host", "")
                    # Always add path and host for ws if they exist, even if default, for round-trip consistency
                    if path:
                        query_params["path"] = path
                    if host:
                        query_params["host"] = host
                elif network == "grpc":
                    grpc_opts = proxy_config.get("grpc-opts", {})
                    service_name = grpc_opts.get("grpc-service-name", "")
                    if service_name:
                        query_params["serviceName"] = service_name

            client_fingerprint = proxy_config.get("client-fingerprint")
            # Always add fp if it exists, to ensure round-trip consistency, as convert_v2ray defaults to "chrome"
            if client_fingerprint:
                query_params["fp"] = client_fingerprint

            query_string = "&".join([f"{k}={quote(str(v))}" for k, v in query_params.items()])

            base_link = f"trojan://{password}@{server}:{port}"
            if query_string:
                return f"{base_link}?{query_string}#{quote(name)}"
            else:
                return f"{base_link}#{quote(name)}"
        elif proxy_type == "vless":
            uuid = proxy_config.get("uuid")
            server = proxy_config.get("server")
            port = proxy_config.get("port")
            if not all([uuid, server, port]):
                return None

            query_params = {}
            name = proxy_config.get("name", f"{server}:{port}")

            # Security/TLS settings
            tls = proxy_config.get("tls", False)
            if tls:
                if "reality-opts" in proxy_config:
                    query_params["security"] = "reality"
                    reality_opts = proxy_config["reality-opts"]
                    if reality_opts.get("public-key"):
                        query_params["pbk"] = reality_opts["public-key"]
                    if reality_opts.get("short-id"):
                        query_params["sid"] = reality_opts["short-id"]
                else:
                    query_params["security"] = "tls"

                if proxy_config.get("client-fingerprint"):
                    query_params["fp"] = proxy_config["client-fingerprint"]
                if proxy_config.get("alpn"):
                    query_params["alpn"] = ",".join(proxy_config["alpn"])
                if proxy_config.get("skip-cert-verify"):
                    query_params["allowInsecure"] = "1"

            if proxy_config.get("servername"):
                query_params["sni"] = proxy_config["servername"]

            # Network settings
            network = proxy_config.get("network", "tcp")
            query_params["type"] = network

            if network == "ws":
                ws_opts = proxy_config.get("ws-opts", {})
                path = ws_opts.get("path", "")
                host = ws_opts.get("headers", {}).get("Host", "")
                if path:
                    query_params["path"] = path
                if host:
                    query_params["host"] = host
            elif network == "grpc":
                grpc_opts = proxy_config.get("grpc-opts", {})
                service_name = grpc_opts.get("grpc-service-name", "")
                if service_name:
                    query_params["serviceName"] = service_name

            if proxy_config.get("flow"):
                query_params["flow"] = proxy_config["flow"]

            query_string = "&".join([f"{k}={quote(str(v))}" for k, v in query_params.items()])

            base_link = f"vless://{uuid}@{server}:{port}"
            if query_string:
                return f"{base_link}?{query_string}#{quote(name)}"
            else:
                return f"{base_link}#{quote(name)}"

        elif proxy_type == "ssr":
            server = proxy_config.get("server")
            port = proxy_config.get("port")
            protocol = proxy_config.get("protocol", "origin")
            cipher = proxy_config.get("cipher")
            obfs = proxy_config.get("obfs", "plain")
            password = proxy_config.get("password")
            name = proxy_config.get("name", f"{server}:{port}")

            if not all([server, port, protocol, cipher, obfs, password]):
                return None

            # Encode password, obfsparam, protoparam, and remarks (name)
            # The password itself is not base64 encoded in the main part of the SSR link.
            # remarks, obfsparam, protoparam are not base64 encoded in the query string.
            # They are directly present.
            # The entire full_ssr_link_body is base64 urlsafe encoded at the end.

            # Construct the main part of the SSR link
            # host:port:protocol:method:obfs:password_enc
            password_enc = Converter.decode_base64_urlsafe(base64.urlsafe_b64encode(password.encode("utf-8"))).decode("utf-8")
            ssr_main_part = f"{server}:{port}:{protocol}:{cipher}:{obfs}:{password_enc}"

            # Construct query parameters
            query_params = {}
            if proxy_config.get("obfs-param"):
                query_params["obfsparam"] = base64.urlsafe_b64encode(proxy_config["obfs-param"].encode("utf-8")).decode("utf-8")
            if proxy_config.get("protocol-param"):
                query_params["protoparam"] = base64.urlsafe_b64encode(proxy_config["protocol-param"].encode("utf-8")).decode("utf-8")
            # remarks (name) is always included
            query_params["remarks"] = base64.urlsafe_b64encode(name.encode("utf-8")).decode("utf-8")
            query_params["group"] = base64.urlsafe_b64encode("MoviePilot".encode("utf-8")).decode("utf-8") # Default group

            query_string = "&".join([f"{k}={quote(str(v))}" for k, v in query_params.items()])

            # Final SSR link: ssr://base64_encoded_main_part?query_string
            full_ssr_link_body = f"{ssr_main_part}/?{query_string}"
            encoded_full_ssr_link_body = base64.urlsafe_b64encode(full_ssr_link_body.encode("utf-8")).decode("utf-8")

            return f"ssr://{encoded_full_ssr_link_body}"

        # Add other proxy types as needed
        return None
