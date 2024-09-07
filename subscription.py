import argparse
import base64
import os
from datetime import datetime
from urllib.parse import unquote
import yaml
import re
import requests
import logging
import schedule
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from flask import Flask, request, jsonify, abort, send_file, make_response

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', encoding='utf-8')

MAX_RULESET_LINES = 999
# SUBSCRIPTION_URL = 'https://dy.jrehnsdnsedgheshes.com/api/v1/client/subscribe?token=62c591b7d56d14e3562a086a12fb8aa0'
SUBSCRIPTION_URL = 'https://fbapiv2.fbsublink.com/flydsubal/2MnqdnLFGHCs5sLp?sub=2&extend=1'
CUSTOM_PROFILE_URL = 'https://raw.githubusercontent.com/ttshmily/ClashCustomRule/master/my_ruleset'
SUBSCRIPTION_USERINFO = None

logging.info(f"Subscription URL: {SUBSCRIPTION_URL}")
logging.info(f"Default profile URL: {CUSTOM_PROFILE_URL}")

app = Flask(__name__)


@dataclass
class ProxyConfig:
    name: str
    type: str
    server: str
    port: int
    cipher: str
    password: str
    udp: str = 'true'


def fetch_remote_content(url: str) -> Optional[str]:
    global SUBSCRIPTION_USERINFO
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        if "subscription-userinfo" in response.headers.keys():
            SUBSCRIPTION_USERINFO = response.headers['subscription-userinfo']
        return response.text.strip()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching content from {url}: {e}")
        return None


def decode_clash_subscription(url: str) -> Optional[str]:
    content = fetch_remote_content(url)
    if content:
        try:
            return base64.b64decode(content).decode('utf-8').strip()
        except Exception as e:
            logger.error(f"Error decoding clash subscription: {e}")
    return None


# def parse_shadowsocks_url(ss_url: str) -> Optional[ProxyConfig]:
#     if not ss_url.startswith('ss://'):
#         logger.warning(f"Invalid Shadowsocks URL: {ss_url}")
#         return None
#
#     ss_url = ss_url[5:]
#     encoded_part, name_part = ss_url.split('#', 1)
#     name = unquote(name_part).strip()
#
#     try:
#         cipher_password, server_port = encoded_part.split('@')
#         cipher, password = base64.urlsafe_b64decode(cipher_password).decode('utf-8').split(':')
#         server, port = server_port.split(':')
#
#         return ProxyConfig(
#             name=name,
#             type='ss',
#             server=server,
#             port=int(port),
#             cipher=cipher,
#             password=password
#         )
#     except Exception as e:
#         logger.error(f"Error parsing Shadowsocks URL: {e}")
#         return None


def parse_shadowsocks_url_new(ss_url: str) -> Optional[ProxyConfig]:
    if not ss_url.startswith('ss://'):
        logger.warning(f"Invalid Shadowsocks URL: {ss_url}")
        return None

    ss_url = ss_url[5:]
    encoded_part, name_part = ss_url.split('#', 1)
    name = unquote(name_part).strip()

    try:
        cipher, host_part, port = base64.urlsafe_b64decode(encoded_part).decode('utf-8').split(':')
        password, server = host_part.split('@')

        if not server:
            logger.warning(f"Invalid Shadowsocks server: {name}")
            return None

        return ProxyConfig(
            name=name,
            type='ss',
            server=server.replace('fbnode-all', 'pnd6xm1ljcfpc3b-fbnode'),
            port=int(port),
            cipher=cipher,
            password=password
        )
    except Exception as e:
        logger.error(f"Error parsing Shadowsocks URL: {e}")
        return None


def load_clash_proxies(subscription_url: str, fallback_file_name: str = 'proxies.yaml') -> tuple[Dict, List[str]]:
    proxy_names = []
    config = {}

    subscription_content = decode_clash_subscription(subscription_url)
    if not subscription_content:
        if fallback_file_name:
            try:
                fallback_file_path = os.path.join(root_dir, fallback_file_name)
                with open(fallback_file_path, 'r', encoding='utf-8') as source:
                    config = yaml.safe_load(source)
                logger.info(f"Loaded YAML configuration from {fallback_file_path}")
                proxy_names = [proxy['name'] for proxy in config.get('proxies', [])
                               if 'name' in proxy]
                format_and_save_yaml(config, 'proxies.yaml')
            except Exception as e:
                logger.error(f"Error loading fallback file: {e}")
    else:
        proxies = []
        for line in subscription_content.split('\n'):
            proxy_config = parse_shadowsocks_url_new(line)
            if proxy_config:
                proxy_names.append(proxy_config.name)
                proxies.append(proxy_config.__dict__)
        config['proxies'] = proxies
        logger.info(f"Loaded YAML configuration from {subscription_url}")
        logger.info(f"subscription_userinfo from {subscription_url}: {SUBSCRIPTION_USERINFO}")
        format_and_save_yaml(config, 'proxies.yaml')
    return config, proxy_names


def parse_ruleset(line: str) -> List[str]:
    _, ruleset_info = line.split('=', 1)
    group_name, url = ruleset_info.split(',', 1)
    url = url.strip()
    processed_rules = []

    if url.startswith('[]'):
        pay_load = url.strip('[]')
        if pay_load == 'FINAL':
            pay_load = 'MATCH'
        processed_rules.append(f"{pay_load},{group_name}")
    elif url.startswith('https://'):
        ruleset_content = fetch_remote_content(url)
        if ruleset_content:
            for rule_line in ruleset_content.splitlines():
                if rule_line.startswith('#'):
                    continue
                parts = rule_line.strip().split(',')
                # if parts[0] in ['USER-AGENT', 'URL-REGEX']:
                #     continue
                if len(parts) == 2:
                    processed_rules.append(f"{rule_line.strip()},{group_name}")
                elif len(parts) >= 3:
                    key, t, *options = parts
                    rule = f"{key},{t},{group_name}"
                    if 'no-resolve' in options:
                        rule += ',no-resolve'
                    processed_rules.append(rule)
    return processed_rules


def parse_proxy_group(line: str, all_proxy_names: List[str]) -> Dict[str, Any]:
    _, group_info = line.split('=', 1)
    parts = group_info.split('`')
    group_name, group_type, *proxies = parts

    group = {
        'name': group_name,
        'type': group_type,
        'proxies': []
    }

    if group_type in ['url-test', 'fallback', 'load-balance']:
        url_test_para = proxies.pop()
        url = proxies.pop()
        interval = int(url_test_para.split(',', 1)[0])
        group.update({
            'url': url,
            'interval': interval
        })

    for proxy in proxies:
        if not proxy.startswith('[]'):
            pattern = re.compile(proxy, re.IGNORECASE)
            matched_proxies = [p for p in all_proxy_names if pattern.search(p)]
            group['proxies'].extend(matched_proxies)
        else:
            group['proxies'].append(proxy.strip('[]'))
    return group


def generate_profile(subscription_url: str, fallback_subscription_file_path: str,
                     customized_config_url: str) -> Optional[Dict[str, List]]:
    rules = []
    proxy_groups = []

    prepared_config, all_proxy_names = load_clash_proxies(subscription_url, fallback_subscription_file_path)
    proxies = prepared_config.get('proxies', [])
    file_content = fetch_remote_content(customized_config_url)
    if not file_content:
        logger.error(f"Failed to download configuration from {customized_config_url}")
        return None
    for n, line in enumerate(file_content.splitlines()):
        logger.info(f"Processing line {n + 1}: {line}")
        if line.startswith('ruleset=') and n < MAX_RULESET_LINES:
            rules.extend(parse_ruleset(line))
        elif line.startswith('custom_proxy_group='):
            proxy_groups.append(parse_proxy_group(line, all_proxy_names))
    return {'proxies': proxies, 'proxy-groups': proxy_groups, 'rules': rules}


def format_and_save_yaml(data: Dict, file_name: str = 'custom.yaml') -> str:
    formatted_lines = []
    for key, value in data.items():
        formatted_lines.append(f"{key}:")
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    formatted_item = ', '.join(
                        [f"{k}: '{v}'" if k == 'name' or k == 'url' and isinstance(v, str) else f"{k}: {v}" for k, v in
                         item.items()]
                    )
                    formatted_lines.append(f"    - {{ {formatted_item} }}")
                else:
                    formatted_lines.append(f"    - '{item}'")
    content = '\n'.join(formatted_lines)
    yaml_file_path = os.path.join(root_dir, file_name)
    with open(yaml_file_path, 'w', encoding='utf-8') as f:
        f.write(content)
        logger.info(f"YAML configuration saved to {yaml_file_path}")
    return content


def generate_config_to_file(subscription_url: str, custom_profile_url: str,
                            fallback_file_path: str, output_file_path: str) -> Dict[str, Any]:
    try:
        new_config = generate_profile(subscription_url, fallback_file_path, custom_profile_url)
        if not new_config:
            raise ValueError("Failed to generate or parse the configuration files")

        basename_rocket_config = f"rocket_{os.path.basename(output_file_path)}"
        format_and_save_yaml(new_config, basename_rocket_config)

        new_config['rules'] = [r for r in new_config['rules'] if
                               not r.startswith('USER-AGENT') and not r.startswith('URL-REGEX')]
        basename_clash_config = f"clash_{os.path.basename(output_file_path)}"
        format_and_save_yaml(new_config, basename_clash_config)

        return {
            "message": "Configuration generated successfully",
            "clash_download_url": f"/download_config/{basename_clash_config}",
            "rocket_download_url": f"/download_config/{basename_rocket_config}"
        }
    except ValueError as ve:
        logger.error(f"Value error: {str(ve)}")
        raise
    except IOError as ioe:
        logger.error(f"IO error when saving configuration: {str(ioe)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise


@app.route('/generate_clash_config', methods=['POST'])
def api_generate_clash_config():
    """
        curl -X POST -H "Content-Type: application/json" -d '{
          "subscription_url": "https://example.com/subscription",
          "custom_profile_url": "https://example.com/custom_profile",
          "output_file_path": "my_config.yaml"
        }' http://localhost:5001/generate_clash_config
    """
    data = request.json

    subscription_url = data.get('subscription_url', SUBSCRIPTION_URL)
    custom_profile_url = data.get('custom_profile_url', CUSTOM_PROFILE_URL)
    if not subscription_url or not custom_profile_url:
        return jsonify({"error": "Missing required parameters"}), 400

    fallback_file_path = data.get('fallback_file_path', 'proxies.yaml')
    output_file_path = data.get('output_file_path', 'custom.yaml')

    try:
        result = generate_config_to_file(subscription_url, custom_profile_url, fallback_file_path,
                                         output_file_path)
        response = jsonify(result)
        response.status_code = 200
        return response
    except Exception as e:
        logger.error(f"Error generating configuration: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/download_config/<filename>', methods=['GET'])
def api_download_config(filename):
    try:
        # 确保文件名是安全的
        safe_filename = os.path.basename(filename)
        yaml_file_path = os.path.join(root_dir, safe_filename)

        # 检查文件是否存在
        if not os.path.exists(yaml_file_path):
            safe_filename = 'proxies.yaml'
            yaml_file_path = os.path.join(root_dir, safe_filename)

        if not os.path.exists(yaml_file_path):
            abort(404, description="File not found")

        if not yaml_file_path.endswith('.yaml'):
            abort(403, description="Access denied")
        # 发送文件
        response = make_response(send_file(str(yaml_file_path), as_attachment=True, download_name=safe_filename))
        response.headers['subscription-userinfo'] = SUBSCRIPTION_USERINFO
        return response
    except Exception as e:
        logger.error(f"Error downloading file: {str(e)}")
        abort(500, description="Internal server error")


@app.route('/ping_status', methods=['GET'])
def health_check():
    logger.info("Received ping request")
    return jsonify({"status": "healthy"}), 200


def scheduled_config_update():
    try:
        logger.info("Starting scheduled config update task...")
        generate_config_to_file(SUBSCRIPTION_URL, CUSTOM_PROFILE_URL, 'proxies.yaml', 'custom.yaml')
        logger.info("Scheduled config update completed successfully")
    except Exception as e:
        logger.error(f"Error in scheduled config update: {str(e)}")


def run_schedule():
    while True:
        seconds_to_wait = log_next_schedule()
        schedule.run_pending()
        reminder_second = max(seconds_to_wait - 5, 10)
        logger.info(f"Next reminder will show after {reminder_second} seconds")
        time.sleep(reminder_second)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Clash Config Service")
    parser.add_argument('-p', '--port', type=int, default=5001,
                        help='Port to run the service on (default: 5001)')
    parser.add_argument('-l', '--log_path', type=str, default=os.getcwd(),
                        help='Location to store the service log')
    return parser.parse_args()


def setup_logging(log_path: str):
    l = logging.getLogger()
    h = logging.FileHandler(os.path.join(log_path, os.path.basename('clash_config_service.log')), encoding='utf-8')
    f = logging.Formatter('%(asctime)s - %(levelname)-5s - [%(funcName)s]: %(message)s', datefmt='%m-%d %H:%M:%S')
    h.setFormatter(f)
    h.setLevel(logging.INFO)
    l.addHandler(h)
    return l


def log_next_schedule():
    next_run = schedule.next_run()
    if next_run:
        now = datetime.now()
        time_until_next_run = next_run - now
        total_seconds = int(time_until_next_run.total_seconds())
        if total_seconds < 0:
            total_seconds = 0
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        logger.info(f"Next Scheduled: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"Time until next run: {hours:02d}:{minutes:02d}:{seconds:02d}")
        return total_seconds
    else:
        logger.info("No scheduled tasks")
        return 10


def log_buddha():
    buddha = """
                   _ooOoo_
                  o8888888o
                  88" . "88
                  (| -_- |)
                  O\  =  /O
               ____/`---'\____
             .'  \\|     |//  `.
            /  \\|||  :  |||//  \\
           /  _||||| -:- |||||-  \\
           |   | \\\  -  /// |   |
           | \_|  ''\---/''  |   |
           \  .-\__  `-`  ___/-. /
         ___`. .'  /--.--\  `. . __
      ."" '<  `.___\_<|>_/___.'  >'"".
     | | :  `- \`.;`\ _ /`;.`/ - ` : | |
     \  \ `-.   \_ __\ /__ _/   .-` /  /
======`-.____`-.___\_____/___.-`____.-'======
                   `=---='
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            佛祖保佑       永无BUG
"""
    for line in buddha.split('\n'):
        logging.info(line)


if __name__ == "__main__":
    args = parse_arguments()

    root_dir = args.log_path.strip()
    logger = setup_logging(log_path=root_dir)

    log_buddha()
    logger.info(f"Starting Service from： {root_dir}")

    # 设置定时任务，每1小时运行一次
    schedule.every(1).hours.do(scheduled_config_update)

    # 在后台线程中运行定时任务
    import threading

    scheduler_thread = threading.Thread(target=run_schedule, daemon=True)
    scheduler_thread.start()

    scheduled_config_update()

    app.root_path = root_dir
    app.run(debug=False, host='0.0.0.0', port=args.port)