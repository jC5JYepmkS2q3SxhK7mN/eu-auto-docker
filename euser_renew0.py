#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EUserv 自动续期脚本 - 多账号多线程版本 (集成 2FA 两步验证防邮箱轰炸)
带详细执行过程输出与 Telegram 双端同步展示 (无遮掩版 + GitHub Cron 动态篡改)
"""

import os
import sys
import re
import json
import time
import threading
import logging
import base64
import hmac
import struct
from typing import Dict, Tuple, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from PIL import Image
import ddddocr
import requests
from bs4 import BeautifulSoup
from imap_tools import MailBox

# ================== 日志配置 ==================
_debug_env = os.getenv("DEBUG", "").lower()
DEBUG_MODE = _debug_env in ("true", "1", "yes", "html")
log_level = logging.DEBUG if DEBUG_MODE else logging.INFO

logging.basicConfig(
    level=log_level,
    format='%(asctime)s [%(threadName)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

SKIP_CONTRACTS = [x.strip() for x in os.getenv("SKIP_CONTRACTS", "").split(",") if x.strip()]
if SKIP_CONTRACTS:
    logger.info(f"配置了跳过合同列表: {SKIP_CONTRACTS}")

if not hasattr(Image, 'ANTIALIAS'):
    Image.ANTIALIAS = Image.Resampling.LANCZOS

ocr = ddddocr.DdddOcr(show_ad=False)
ocr_lock = threading.Lock()

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"

# ============== 2FA 算法实现 ==============
def _hotp(key: str, counter: int, digits: int = 6, digest: str = "sha1") -> str:
    """HOTP 算法实现"""
    key_bytes = base64.b32decode(key.upper() + "=" * ((8 - len(key)) % 8))
    counter_bytes = struct.pack(">Q", counter)
    mac = hmac.new(key_bytes, counter_bytes, digest).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">L", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary)[-digits:].zfill(digits)

def _totp(key: str, time_step: int = 30, digits: int = 6, digest: str = "sha1") -> str:
    """TOTP 算法实现 (生成 6 位动态验证码)"""
    return _hotp(key, int(time.time() / time_step), digits, digest)
# ==========================================

# ============== 配置数据类 ==============
class AccountConfig:
    def __init__(self, email, password, euserv_2fa='', imap_server='imap.gmail.com', email_password=''):
        self.email = email
        self.password = password
        self.euserv_2fa = euserv_2fa
        self.imap_server = imap_server
        self.email_password = email_password if email_password else password

class GlobalConfig:
    def __init__(self, telegram_bot_token="", telegram_chat_id="", max_workers=3, max_login_retries=3):
        self.telegram_bot_token = telegram_bot_token
        self.telegram_chat_id = telegram_chat_id
        self.max_workers = max_workers
        self.max_login_retries = max_login_retries

# ============== 配置区 ==============
GLOBAL_CONFIG = GlobalConfig(
    telegram_bot_token=os.getenv("TG_BOT_TOKEN"),
    telegram_chat_id=os.getenv("TG_CHAT_ID"),
    max_workers=3,
    max_login_retries=3
)

def get_imap_server(email: str) -> str:
    if "@qq.com" in email or "@foxmail.com" in email:
        return "imap.qq.com"
    elif "@163.com" in email:
        return "imap.163.com"
    elif "@outlook.com" in email or "@hotmail.com" in email:
        return "outlook.office365.com"
    return "imap.gmail.com"

_email = os.getenv("EUSERV_EMAIL", "")
ACCOUNTS = [
    AccountConfig(
        email=_email,
        password=os.getenv("EUSERV_PASSWORD", ""),
        euserv_2fa=os.getenv("EUSERV_2FA", ""),
        imap_server=get_imap_server(_email),
        email_password=os.getenv("EMAIL_PASS", "")
    ),
]

def recognize_and_calculate(captcha_image_url: str, session: requests.Session) -> Optional[str]:
    try:
        response = session.get(captcha_image_url)
        image_bytes = response.content
        
        with ocr_lock:
            text = ocr.classification(image_bytes).strip()
        
        raw_text = text.strip()
        text = raw_text.replace(' ', '').upper()

        if re.fullmatch(r'[A-Z0-9]+', text):
            return raw_text.strip()

        pattern = r'^(\d+)([+\-*/×xX÷/])(\d+|[A-Z])$'
        match = re.match(pattern, text)

        if not match:
            return raw_text.strip()

        left_str, op, right_str = match.groups()
        left = int(left_str)

        if right_str.isdigit():
            right = int(right_str)
        else:
            if 'A' <= right_str <= 'Z':
                right = ord(right_str) - ord('A') + 10
            else:
                return raw_text.strip()

        if op in {'*', '×', 'X', 'x'}:
            result = left * right
        elif op == '+':
            result = left + right
        elif op == '-':
            result = left - right
        elif op in {'/', '÷'}:
            if right == 0 or left % right != 0:
                return raw_text.strip()
            result = left // right
        else:
            return raw_text.strip()

        return str(result)
    except Exception as e:
        logger.error(f"验证码识别错误: {e}", exc_info=True)
        return None

def get_euserv_pin(email: str, email_password: str, imap_server: str, after_time: datetime = None, pin_type: str = 'login', log_callback=None) -> Optional[str]:
    max_retries = 12
    retry_interval = 5
    
    if pin_type == 'renew':
        subject_keywords = ['security check', 'confirmation']
        type_name = "续期"
    else:
        subject_keywords = ['attempted login', 'login']
        type_name = "登录"
    
    if log_callback: log_callback(f"正在连接邮箱 {email} 获取 {type_name} PIN 码...")
    
    for i in range(max_retries):
        try:
            if i > 0:
                time.sleep(retry_interval)
                
            with MailBox(imap_server).login(email, email_password) as mailbox:
                for msg in mailbox.fetch(limit=10, reverse=True):
                    if 'euserv' not in msg.from_.lower():
                        continue
                    
                    subject_lower = msg.subject.lower()
                    if not any(keyword in subject_lower for keyword in subject_keywords):
                        continue
                    
                    if after_time and msg.date:
                        email_dt = msg.date
                        if email_dt.tzinfo is None:
                            email_dt = email_dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
                        
                        filter_dt = after_time
                        if filter_dt.tzinfo is None:
                            filter_dt = filter_dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
                        
                        if email_dt.timestamp() < (filter_dt.timestamp() - 120):
                            continue
                    
                    match = re.search(r'PIN:\s*\n?(\d{6})', msg.text) or re.search(r'PIN.*?(\d{6})', msg.text, re.DOTALL)
                    if match:
                        if log_callback: log_callback(f"成功提取到 PIN 码: {match.group(1)}")
                        return match.group(1)
                    
                    match_fallback = re.search(r'\b(\d{6})\b', msg.text)
                    if match_fallback:
                        if log_callback: log_callback(f"成功提取到 PIN 码: {match_fallback.group(1)}")
                        return match_fallback.group(1)
                            
        except Exception:
            pass
            
    if log_callback: log_callback(f"获取 PIN 码超时失败！")
    return None

class EUserv:
    def __init__(self, config: AccountConfig, log_callback):
        self.config = config
        self.session = requests.Session()
        self.sess_id = None
        self.log = log_callback
        
    def login(self) -> bool:
        self.log(f"正在登录账号：{self.config.email}")
        
        headers = {
            'user-agent': USER_AGENT,
            'origin': 'https://www.euserv.com'
        }
        url = "https://support.euserv.com/index.iphp"
        captcha_url = "https://support.euserv.com/securimage_show.php"
        
        try:
            sess = self.session.get(url, headers=headers)
            sess_id_match = re.search(r'sess_id["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{30,100})["\']?', sess.text)
            if not sess_id_match:
                sess_id_match = re.search(r'sess_id=([a-zA-Z0-9]{30,100})', sess.text)
            
            if not sess_id_match:
                self.log("❌ 无法获取网页 session_id")
                return False
            
            sess_id = sess_id_match.group(1)
            self.session.get("https://support.euserv.com/pic/logo_small.png", headers=headers)
            
            login_data = {
                'email': self.config.email,
                'password': self.config.password,
                'form_selected_language': 'en',
                'Submit': 'Login',
                'subaction': 'login',
                'sess_id': sess_id
            }
            
            response = self.session.post(url, headers=headers, data=login_data)
            response.raise_for_status()

            if 'Please check email address/customer ID and password' in response.text:
                self.log("❌ 账号或密码错误")
                return False
            if 'kc2_login_iplock_cdown' in response.text:
                self.log("❌ 尝试过多 IP被暂时锁定")
                return False
            
            if 'captcha' in response.text.lower():
                self.log("▲ 检测到需要图片验证码，正在识别...")
                captcha_max_retries = 3
                captcha_success = False
                
                for captcha_attempt in range(captcha_max_retries):
                    captcha_code = recognize_and_calculate(captcha_url, self.session)
                    if not captcha_code:
                        if captcha_attempt < captcha_max_retries - 1:
                            time.sleep(2)
                        continue
                    
                    self.log(f"验证码识别结果: {captcha_code}")
                    captcha_data = {
                        'subaction': 'login',
                        'sess_id': sess_id,
                        'captcha_code': captcha_code
                    }
                    
                    response = self.session.post(url, headers=headers, data=captcha_data)
                    response.raise_for_status()
                    
                    if 'captcha' not in response.text.lower():
                        captcha_success = True
                        break
                    else:
                        if captcha_attempt < captcha_max_retries - 1:
                            time.sleep(2)
                
                if not captcha_success:
                    self.log("❌ 验证码多次识别失败")
                    return False
            
            if 'authenticator app' in response.text.lower() or 'enter the pin that is shown' in response.text.lower():
                self.log("▲ 检测到需要 2FA (Authenticator App) 验证")
                if not self.config.euserv_2fa:
                    self.log("❌ 未配置 EUSERV_2FA 密钥，无法登录！")
                    return False
                
                two_fa_code = _totp(self.config.euserv_2fa)
                self.log(f"已利用本地算法生成 2FA 动态密码：{two_fa_code}")
                soup = BeautifulSoup(response.text, "html.parser")
                hidden_inputs = soup.find_all("input", type="hidden")
                two_fa_data = {inp["name"]: inp.get("value", "") for inp in hidden_inputs}
                two_fa_data["pin"] = two_fa_code
                
                response = self.session.post(url, headers=headers, data=two_fa_data)
                response.raise_for_status()
                
            elif 'PIN that you receive via email' in response.text:
                self.log("▲ 检测到需要邮件 PIN 码验证")
                pin_request_time = datetime.now()
                time.sleep(3)
                pin = get_euserv_pin(self.config.email, self.config.email_password, self.config.imap_server, after_time=pin_request_time, pin_type='login', log_callback=self.log)
                if not pin:
                    self.log("❌ 获取登录 PIN 码失败")
                    return False
                
                soup = BeautifulSoup(response.text, "html.parser")
                login_confirm_data = {
                    'pin': pin,
                    'sess_id': sess_id,
                    'Submit': 'Confirm',
                    'subaction': 'login',
                    'c_id': soup.find("input", {"name": "c_id"})["value"],
                }
                response = self.session.post(url, headers=headers, data=login_confirm_data)
                response.raise_for_status()

            success_checks = ['Hello' in response.text, 'Confirm or change your customer data here' in response.text, 'logout' in response.text.lower() and 'customer' in response.text.lower()]
            if any(success_checks):
                self.sess_id = sess_id
                self.log(f"✓ 账号 {self.config.email} 登录成功")
                return True
            
            self.log(f"❌ 账号 {self.config.email} 登录最终失败，未检测到成功标志")
            return False
                
        except Exception as e:
            self.log(f"❌ 登录过程发生异常: {e}")
            return False

    def get_servers(self) -> Dict[str, Tuple[bool, str]]:
        self.log(f"正在获取账号 {self.config.email} 的服务器列表...")
        if not self.sess_id:
            return {}
        
        url = f"https://support.euserv.com/index.iphp?sess_id={self.sess_id}"
        headers = {'user-agent': USER_AGENT, 'origin': 'https://www.euserv.com'}
        
        try:
            detail_response = self.session.get(url=url, headers=headers)
            detail_response.raise_for_status()

            soup = BeautifulSoup(detail_response.text, 'html.parser')
            servers = {}

            selector = '#kc2_order_customer_orders_tab_content_1 .kc2_order_table.kc2_content_table tr, #kc2_order_customer_orders_tab_content_2 .kc2_order_table.kc2_content_table tr'
            for tr in soup.select(selector):
                server_id = tr.select('.td-z1-sp1-kc')
                if len(server_id) != 1:
                    continue
                
                row_text = tr.get_text().lower()
                server_id_text = server_id[0].get_text().strip()
                
                if server_id_text in SKIP_CONTRACTS or 'sync' in row_text and 'share' in row_text:
                    continue
                
                action_containers = tr.select('.td-z1-sp2-kc .kc2_order_action_container')
                if not action_containers:
                    continue
                    
                action_text = action_containers[0].get_text()
                can_renew = action_text.find("Contract extension possible from") == -1
                can_renew_date = ""
                
                if not can_renew:
                    date_pattern = r'\b\d{4}-\d{2}-\d{2}\b'
                    match = re.search(date_pattern, action_text)
                    if match:
                        can_renew_date = match.group(0)
                        can_renew = datetime.today().date() >= datetime.strptime(can_renew_date, "%Y-%m-%d").date()

                servers[server_id_text] = (can_renew, can_renew_date)
            
            self.log(f"✓ 账号 {self.config.email} 找到 {len(servers)} 台服务器")
            return servers
        except Exception as e:
            self.log(f"❌ 获取服务器列表报错: {e}")
            return {}
    
    def renew_server(self, order_id: str) -> bool:
        self.log(f"➤ 开始执行服务器 {order_id} 的续期流程...")
        url = "https://support.euserv.com/index.iphp"
        headers = {
            'user-agent': USER_AGENT,
            'Host': 'support.euserv.com',
            'origin': 'https://support.euserv.com',
            'Referer': 'https://support.euserv.com/index.iphp'
        }
        
        try:
            data = {'Submit': 'Extend contract', 'sess_id': self.sess_id, 'ord_no': order_id, 'subaction': 'choose_order', 'show_contract_extension': '1', 'choose_order_subaction': 'show_contract_details'}
            self.session.post(url, headers=headers, data=data).raise_for_status()
            
            pin_request_time = datetime.now()
            data = {'sess_id': self.sess_id, 'subaction': 'show_kc2_security_password_dialog', 'prefix': 'kc2_customer_contract_details_extend_contract_', 'type': '1'}
            self.session.post(url, headers=headers, data=data).raise_for_status()
            
            time.sleep(5)
            pin = get_euserv_pin(self.config.email, self.config.email_password, self.config.imap_server, after_time=pin_request_time, pin_type='renew', log_callback=self.log)
            if not pin: 
                self.log(f"❌ 服务器 {order_id} 续期中止，无法获取授权 PIN 码")
                return False
        
            data = {'sess_id': self.sess_id, 'auth': pin, 'subaction': 'kc2_security_password_get_token', 'prefix': 'kc2_customer_contract_details_extend_contract_', 'type': '1', 'ident': 'kc2_customer_contract_details_extend_contract_' + order_id}
            resp3 = self.session.post(url, headers=headers, data=data)
            resp3.raise_for_status()

            result = json.loads(resp3.text)
            if result.get('rs') != 'success': 
                self.log(f"❌ 换取续期 Token 失败")
                return False
            token = result['token']['value']
            time.sleep(3)

            data = {'sess_id': self.sess_id, 'subaction': 'kc2_customer_contract_details_get_extend_contract_confirmation_dialog', 'token': token}
            resp4 = self.session.post(url, headers=headers, data=data)
            resp4.raise_for_status()
            
            try:
                dialog_html = ""
                try:
                    result4 = json.loads(resp4.text)
                    if isinstance(result4, dict):
                        if 'html' in result4 and 'value' in result4['html']: dialog_html = result4['html']['value']
                        elif 'value' in result4: dialog_html = result4['value']
                except: dialog_html = resp4.text
                
                data_confirm = {}
                for match in re.finditer(r'<input[^>]+type=["\']hidden["\'][^>]*>', dialog_html, re.IGNORECASE):
                    input_tag = match.group(0)
                    name_match = re.search(r'name=["\']([^"\']+)["\']', input_tag)
                    value_match = re.search(r'value=["\']([^"\']+)["\']', input_tag)
                    if name_match and value_match: data_confirm[name_match.group(1)] = value_match.group(1)

                if 'token' not in data_confirm:
                    token_match = re.search(r'name=["\']token["\']\s+value=["\']([^"\']+)["\']', dialog_html)
                    if token_match: data_confirm['token'] = token_match.group(1)

                headers['Referer'] = 'https://support.euserv.com/index.iphp'
                time.sleep(2)
                resp5 = self.session.post(url, headers=headers, data=data_confirm)
                resp5.raise_for_status()
                
                if "error: token missing" in resp5.text.lower(): 
                    self.log(f"❌ 最终提交失败 (Error: token missing)")
                    return False
                return True
            except Exception as e: 
                self.log(f"❌ 提交续期确认信息异常: {e}")
                return False
        except Exception as e: 
            self.log(f"❌ 续期全流程发生未知异常: {e}")
            return False

def send_telegram(message: str, config: GlobalConfig):
    if not config.telegram_bot_token or not config.telegram_chat_id:
        return
    url = f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage"
    data = {
        "chat_id": config.telegram_chat_id,
        "text": message,
        "parse_mode": "HTML"
    }
    try:
        response = requests.post(url, json=data, timeout=10)
        if response.status_code == 200:
            logger.info("✅ Telegram 通知发送成功")
        else:
            logger.error(f"❌ Telegram 通知失败: {response.status_code}")
    except Exception as e:
        logger.error(f"❌ Telegram 异常: {e}", exc_info=True)

# ==================== 赛博自我修改机制核心函数 ====================
def update_github_workflow_cron(target_date: datetime.date) -> Tuple[bool, str]:
    """通过 GitHub API 自动修改 workflows 里的 cron 表达式"""
    token = os.getenv("PAT_WITH_WORKFLOW_SCOPE")
    repo = os.getenv("GITHUB_REPO")
    
    if not token or not repo:
        logger.warning("⚠️ 未配置 PAT_WITH_WORKFLOW_SCOPE 或 GITHUB_REPO，无法自动修改 Cron。")
        return False, "未配置 GitHub API 密钥"

    file_path = ".github/workflows/euserv-run.yml"
    api_url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    try:
        resp = requests.get(api_url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        sha = data['sha']
        content = base64.b64decode(data['content']).decode('utf-8')

        # 生成新的 cron 表达式 (UTC 0点27分，完美错开整点)
        cron_expr = f"27 0 {target_date.day} {target_date.month} *"
        
        new_content = re.sub(r"cron:\s*'.*?'", f"cron: '{cron_expr}'", content, count=1)
        
        if new_content == content:
            logger.info(f"📅 Cron 表达式已经是 '{cron_expr}'，无需更新。")
            return True, f"已是最新 {cron_expr}"

        put_data = {
            "message": f"🤖 Auto-update cron schedule to {target_date.strftime('%Y-%m-%d')} ({cron_expr})",
            "content": base64.b64encode(new_content.encode('utf-8')).decode('utf-8'),
            "sha": sha
        }
        put_resp = requests.put(api_url, headers=headers, json=put_data)
        put_resp.raise_for_status()
        
        logger.info(f"✅ 成功修改 GitHub Workflow！下次唤醒时间已锁定为: {target_date.strftime('%Y-%m-%d')} (Cron: {cron_expr})")
        return True, f"成功修改为 {cron_expr}"

    except Exception as e:
        logger.error(f"❌ 更新 GitHub Workflow 失败: {e}", exc_info=True)
        return False, f"API 报错: {e}"
# =================================================================

def process_account(account_config: AccountConfig, global_config: GlobalConfig) -> Dict:
    result = {
        'email': account_config.email,
        'success': False,
        'servers': {},
        'renew_results': [],
        'error': None,
        'process_logs': []
    }
    
    # 构建双端收集器 (打印到控制台 + 收集发给 TG)
    def add_log(msg):
        logger.info(msg)
        result['process_logs'].append(f"INFO: {msg}")

    try:
        euserv = EUserv(account_config, add_log)
        
        login_success = False
        for attempt in range(global_config.max_login_retries):
            if attempt > 0:
                time.sleep(5)
            if euserv.login():
                login_success = True
                break
        
        if not login_success:
            result['error'] = "登录失败"
            return result
        
        servers = euserv.get_servers()
        result['servers'] = servers
        
        if not servers:
            result['error'] = "未找到任何服务器"
            result['success'] = True
            return result
        
        for order_id, (can_renew, can_renew_date) in servers.items():
            add_log(f"检查服务器: {order_id}")
            if can_renew:
                add_log(f"⏰ 服务器 {order_id} 可以续期，开始处理...")
                if euserv.renew_server(order_id):
                    add_log(f"✅ 服务器 {order_id} 续期成功")
                    result['renew_results'].append({
                        'order_id': order_id,
                        'success': True,
                        'message': f"✅ 服务器 {order_id} 续期成功"
                    })
                else:
                    add_log(f"❌ 服务器 {order_id} 续期失败")
                    result['renew_results'].append({
                        'order_id': order_id,
                        'success': False,
                        'message': f"❌ 服务器 {order_id} 续期失败"
                    })
                break
            else:
                add_log(f"✓ 服务器 {order_id} 暂不需要续期（可续期日期: {can_renew_date}）")
        
        result['success'] = True
        
    except Exception as e:
        logger.error(f"处理账号 {account_config.email} 时发生异常: {e}", exc_info=True)
        result['error'] = str(e)
    
    return result


def main():
    logger.info("=" * 60)
    logger.info("EUserv 多账号自动续期脚本（多线程版本 + 2FA防轰炸 + GitHub Cron 动态修改 + 明文追踪）")
    logger.info(f"执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"配置账号数: {len(ACCOUNTS)}")
    logger.info("=" * 60)
    
    if not ACCOUNTS:
        logger.error("❌ 未配置任何账号")
        sys.exit(1)
    
    all_results = []
    with ThreadPoolExecutor(max_workers=GLOBAL_CONFIG.max_workers) as executor:
        future_to_account = {
            executor.submit(process_account, account, GLOBAL_CONFIG): account 
            for account in ACCOUNTS
        }
        
        for future in as_completed(future_to_account):
            account = future_to_account[future]
            try:
                result = future.result()
                all_results.append(result)
            except Exception as e:
                logger.error(f"处理账号 {account.email} 时发生未预期的异常: {e}", exc_info=True)
                all_results.append({
                    'email': account.email,
                    'success': False,
                    'error': f"未预期的异常: {str(e)}",
                    'process_logs': []
                })
    
    message_parts = [f"<b>🔄 eu-auto-docker github 多账号续期报告</b>\n"]
    message_parts.append(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    message_parts.append(f"处理账号数: {len(all_results)}\n")
    
    for result in all_results:
        email = result['email']
        message_parts.append(f"\n<b>📧 账号: {email}</b>")
        
        # 1. 注入全明文执行过程
        if result.get('process_logs'):
            message_parts.append("\n<b>[执行过程详情]</b>")
            for log_str in result['process_logs']:
                message_parts.append(f"<code>{log_str}</code>")
            message_parts.append("") # 换行留白
        
        if not result['success']:
            error_msg = result.get('error', '未知错误')
            message_parts.append(f"  ❌ 最终处理失败: {error_msg}")
            continue
        
        servers = result.get('servers', {})
        renew_results = result.get('renew_results', [])
        
        # 2. 总结最终结果
        message_parts.append("<b>[最终结果总结]</b>")
        if renew_results:
            for renew_result in renew_results:
                message_parts.append(f"  {renew_result['message']}")
        else:
            message_parts.append("  ✓ 所有服务器均无需续期")
            for order_id, (can_renew, can_renew_date) in servers.items():
                if can_renew_date:
                    message_parts.append(f"    订单 {order_id}: 可续期日期 {can_renew_date}")

    # ==================== 开始提取日期，修改自身 Workflow ====================
    earliest_date = None
    for result in all_results:
        servers = result.get('servers', {})
        for order_id, (can_renew, can_renew_date) in servers.items():
            if can_renew_date and can_renew_date not in ("未知", "未知日期", ""):
                try:
                    dt = datetime.strptime(can_renew_date, "%Y-%m-%d").date()
                    if earliest_date is None or dt < earliest_date:
                        earliest_date = dt
                except ValueError:
                    pass

    if earliest_date:
        message_parts.append(f"\n<b>⚙️ 赛博续命系统动作:</b>")
        success, msg = update_github_workflow_cron(earliest_date)
        if success:
            message_parts.append(f"  ✅ 已将下次唤醒时间自动锁定为: {earliest_date.strftime('%Y-%m-%d')} ({msg})")
            message_parts.append(f"  💡 触发代码重写，完美破除仓库 60 天休眠魔咒！")
        else:
            message_parts.append(f"  ❌ 自动修改唤醒时间失败: {msg}")
    # =========================================================================

    message = "\n".join(message_parts)
    send_telegram(message, GLOBAL_CONFIG)
    
    logger.info("\n" + "=" * 60)
    logger.info("执行完成，Telegram 播报已发送！")
    logger.info("=" * 60)

if __name__ == "__main__":
    main()
