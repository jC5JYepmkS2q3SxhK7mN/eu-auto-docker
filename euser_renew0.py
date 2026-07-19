#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EUserv 自动续期脚本 - 多账号多线程版本 (集成 2FA 两步验证防邮箱轰炸)
支持多账号配置、多线程并发处理、自动登录、验证码识别、2FA动态密码、检查到期状态、自动续期并发送 Telegram 通知
（附带：赛博自我续命机制，自动修改 GitHub Workflow Cron 并防止 60 天停用）
"""

import os
import sys
import io
import re
import json
import time
import threading
import logging
import base64
import hmac
import struct
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from PIL import Image
import ddddocr
import requests
from bs4 import BeautifulSoup
from imap_tools import MailBox

# 配置日志
_debug_env = os.getenv("DEBUG", "").lower()
DEBUG_MODE = _debug_env in ("true", "1", "yes", "html")
SAVE_HTML_MODE = _debug_env == "html"
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

# ====================================

def recognize_and_calculate(captcha_image_url: str, session: requests.Session) -> Optional[str]:
    logger.info("正在处理验证码...")
    try:
        logger.debug("尝试自动识别验证码...")
        response = session.get(captcha_image_url)
        image_bytes = response.content
        
        with ocr_lock:
            text = ocr.classification(image_bytes).strip()
        
        logger.debug(f"OCR 识别文本: {text}")

        raw_text = text.strip()
        text = raw_text.replace(' ', '').upper()

        if re.fullmatch(r'[A-Z0-9]+', text):
            logger.info(f"检测到纯字母数字验证码: {raw_text}")
            return raw_text.strip()

        pattern = r'^(\d+)([+\-*/×xX÷/])(\d+|[A-Z])$'
        match = re.match(pattern, text)

        if not match:
            logger.warning(f"无法解析验证码格式（非纯字母数字也非运算式）: {raw_text}")
            return raw_text.strip()

        left_str, op, right_str = match.groups()
        left = int(left_str)

        if right_str.isdigit():
            right = int(right_str)
        else:
            if 'A' <= right_str <= 'Z':
                right = ord(right_str) - ord('A') + 10
            else:
                logger.warning(f"右边字符无效: {right_str}")
                return raw_text.strip()

        if op in {'*', '×', 'X', 'x'}:
            result = left * right
            op_name = '乘'
        elif op == '+':
            result = left + right
            op_name = '加'
        elif op == '-':
            result = left - right
            op_name = '减'
        elif op in {'/', '÷'}:
            if right == 0:
                logger.warning("除数为0，无法计算")
                return raw_text.strip()
            if left % right != 0:
                logger.warning(f"除法非整除: {left} ÷ {right} = {left / right}")
                return raw_text.strip()
            result = left // right
            op_name = '除'
        else:
            logger.warning(f"未知运算符: {op}")
            return raw_text.strip()

        logger.info(f"验证码计算: {left} {op_name} {right_str} = {result}")
        return str(result)
    except Exception as e:
        logger.error(f"验证码识别错误发生错误: {e}", exc_info=True)
        return None

def get_euserv_pin(email: str, email_password: str, imap_server: str, after_time: datetime = None, pin_type: str = 'login') -> Optional[str]:
    max_retries = 12
    retry_interval = 5
    
    if pin_type == 'renew':
        subject_keywords = ['security check', 'confirmation']
        type_name = "续期"
    else:
        subject_keywords = ['attempted login', 'login']
        type_name = "登录"
    
    logger.info(f"正在从邮箱 {email} 获取{type_name} PIN 码 (最长等待 {max_retries * retry_interval} 秒)...")
    if after_time:
        logger.debug(f"只查找 {after_time.strftime('%H:%M:%S')} 之后的邮件")
    
    for i in range(max_retries):
        try:
            if i > 0:
                logger.info(f"第 {i+1} 次尝试获取邮件...")
                time.sleep(retry_interval)
                
            with MailBox(imap_server).login(email, email_password) as mailbox:
                for msg in mailbox.fetch(limit=10, reverse=True):
                    if 'euserv' not in msg.from_.lower():
                        continue
                    
                    subject_lower = msg.subject.lower()
                    is_target_type = any(keyword in subject_lower for keyword in subject_keywords)
                    if not is_target_type:
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
                        pin = match.group(1)
                        logger.info(f"✅ 提取到{type_name} PIN 码: {pin}")
                        return pin
                    
                    match_fallback = re.search(r'\b(\d{6})\b', msg.text)
                    if match_fallback:
                        pin = match_fallback.group(1)
                        logger.info(f"✅ 提取到{type_name} PIN 码: {pin}")
                        return pin
                            
        except Exception as e:
            logger.warning(f"获取邮件尝试失败: {e}")
            
    logger.error(f"❌ 超时未找到{type_name} PIN 码邮件")
    return None

class EUserv:
    def __init__(self, config: AccountConfig):
        self.config = config
        self.session = requests.Session()
        self.sess_id = None
        
    def login(self) -> bool:
        logger.info(f"正在登录账号: {self.config.email}")
        
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
                logger.error("❌ 无法获取 sess_id")
                return False
            
            sess_id = sess_id_match.group(1)
            logger.debug(f"获取到 sess_id: {sess_id[:20]}...")
            
            logo_png_url = "https://support.euserv.com/pic/logo_small.png"
            self.session.get(logo_png_url, headers=headers)
            
            login_data = {
                'email': self.config.email,
                'password': self.config.password,
                'form_selected_language': 'en',
                'Submit': 'Login',
                'subaction': 'login',
                'sess_id': sess_id
            }
            
            logger.debug("提交登录表单...")
            response = self.session.post(url, headers=headers, data=login_data)
            response.raise_for_status()

            if 'Please check email address/customer ID and password' in response.text:
                logger.error("❌ 用户名或密码错误")
                return False
            if 'kc2_login_iplock_cdown' in response.text:
                logger.error("❌ 密码错误次数过多，账号被锁定，请5分钟后重试")
                return False
            
            # --- 1. 处理图片验证码 ---
            if 'captcha' in response.text.lower():
                captcha_max_retries = 3
                captcha_success = False
                
                for captcha_attempt in range(captcha_max_retries):
                    logger.info(f"⚠️ 需要验证码，正在识别... (第 {captcha_attempt + 1}/{captcha_max_retries} 次)")
                    captcha_code = recognize_and_calculate(captcha_url, self.session)
                    
                    if not captcha_code:
                        logger.warning(f"验证码识别失败 (第 {captcha_attempt + 1} 次)")
                        if captcha_attempt < captcha_max_retries - 1:
                            time.sleep(2)
                        continue
                    
                    captcha_data = {
                        'subaction': 'login',
                        'sess_id': sess_id,
                        'captcha_code': captcha_code
                    }
                    
                    response = self.session.post(url, headers=headers, data=captcha_data)
                    response.raise_for_status()
                    
                    if 'captcha' not in response.text.lower():
                        captcha_success = True
                        logger.info("✅ 验证码通过")
                        break
                    else:
                        logger.warning(f"验证码错误 (第 {captcha_attempt + 1} 次)")
                        if captcha_attempt < captcha_max_retries - 1:
                            time.sleep(2)
                
                if not captcha_success:
                    logger.error(f"❌ 验证码连续 {captcha_max_retries} 次失败，放弃登录")
                    return False
            
            # --- 2. 处理 2FA 验证 (如果用户开启了 Authenticator) ---
            if 'authenticator app' in response.text.lower() or 'enter the pin that is shown' in response.text.lower():
                logger.info("⚠️ 检测到需要 2FA (Authenticator App) 验证")
                if not self.config.euserv_2fa:
                    logger.error("❌ 未配置 EUSERV_2FA Secret 环境变量，无法进行两步验证登录！")
                    return False
                
                two_fa_code = _totp(self.config.euserv_2fa)
                logger.info(f"🔑 已利用本地算法生成 2FA 动态密码: ****{two_fa_code[-2:]}")

                soup = BeautifulSoup(response.text, "html.parser")
                hidden_inputs = soup.find_all("input", type="hidden")
                two_fa_data = {inp["name"]: inp.get("value", "") for inp in hidden_inputs}
                two_fa_data["pin"] = two_fa_code
                
                response = self.session.post(url, headers=headers, data=two_fa_data)
                response.raise_for_status()
                
            # --- 3. 处理传统的邮箱 PIN 验证 (兼容没有开启2FA，或者强制邮件验证的账户) ---
            elif 'PIN that you receive via email' in response.text:
                logger.info("⚠️ 需要邮箱 PIN 验证 (登录阶段)")
                pin_request_time = datetime.now()
                time.sleep(3)
                
                pin = get_euserv_pin(
                    self.config.email,
                    self.config.email_password,
                    self.config.imap_server,
                    after_time=pin_request_time,
                    pin_type='login'
                )
                
                if not pin:
                    logger.error("❌ 邮箱获取 PIN 码失败")
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

            # --- 4. 验证登录是否最终成功 ---
            success_checks = [
                'Hello' in response.text,
                'Confirm or change your customer data here' in response.text,
                'logout' in response.text.lower() and 'customer' in response.text.lower()
            ]
            
            if any(success_checks):
                logger.info(f"✅ 账号 {self.config.email} 登录成功")
                self.sess_id = sess_id
                return True
            else:
                logger.error(f"❌ 账号 {self.config.email} 登录失败")
                return False
                
        except Exception as e:
            logger.error(f"❌ 登录过程出现异常: {e}", exc_info=True)
            return False

    def get_servers(self) -> Dict[str, Tuple[bool, str]]:
        logger.info(f"正在获取账号 {self.config.email} 的服务器列表...")
        
        if not self.sess_id:
            logger.error("❌ 未登录")
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
                
                logger.debug(f"合同 {server_id_text} 行内容: {row_text[:200]}...")
                
                if server_id_text in SKIP_CONTRACTS:
                    logger.info(f"⏭️ 跳过配置的合同: {server_id_text}")
                    continue
                
                if 'sync' in row_text and 'share' in row_text:
                    logger.info(f"⏭️ 跳过 Sync & Share 合同: {server_id_text}")
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
            
            logger.info(f"✅ 账号 {self.config.email} 找到 {len(servers)} 台服务器")
            return servers
            
        except Exception as e:
            logger.error(f"❌ 获取服务器列表失败: {e}", exc_info=True)
            return {}
    
    def renew_server(self, order_id: str) -> bool:
        logger.info(f"正在续期服务器 {order_id}...")
        
        url = "https://support.euserv.com/index.iphp"
        headers = {
            'user-agent': USER_AGENT,
            'Host': 'support.euserv.com',
            'origin': 'https://support.euserv.com',
            'Referer': 'https://support.euserv.com/index.iphp'
        }
        
        try:
            logger.info("步骤1: 选择订单...")
            data = {
                'Submit': 'Extend contract',
                'sess_id': self.sess_id,
                'ord_no': order_id,
                'subaction': 'choose_order',
                'show_contract_extension': '1',
                'choose_order_subaction': 'show_contract_details'
            }
            logger.debug(f"[步骤1] 请求参数: {data}")
            resp1 = self.session.post(url, headers=headers, data=data)
            resp1.raise_for_status()
            logger.debug(f"[步骤1] 响应状态: {resp1.status_code}, 长度: {len(resp1.text)}")
            
            logger.info("步骤2: 触发发送 PIN...")
            pin_request_time = datetime.now()
            logger.debug(f"[步骤2] PIN 请求时间: {pin_request_time.strftime('%Y-%m-%d %H:%M:%S')}")
            data = {
                'sess_id': self.sess_id,
                'subaction': 'show_kc2_security_password_dialog',
                'prefix': 'kc2_customer_contract_details_extend_contract_',
                'type': '1'
            }
            logger.debug(f"[步骤2] 请求参数: {data}")
            resp2 = self.session.post(url, headers=headers, data=data)
            resp2.raise_for_status()
            logger.debug(f"[步骤2] 响应状态: {resp2.status_code}, 长度: {len(resp2.text)}")
            
            logger.info("步骤3: 等待并获取续期 PIN 码 (此步骤EUServ依然强制发邮件)...")
            time.sleep(5)
            pin = get_euserv_pin(
                self.config.email,
                self.config.email_password,
                self.config.imap_server,
                after_time=pin_request_time,
                pin_type='renew'
            )
            
            if not pin:
                logger.error(f"❌ 获取续期 PIN 码失败")
                return False
        
            logger.info("步骤4: 验证 PIN 获取 token...")
            data = {
                'sess_id': self.sess_id,
                'auth': pin,
                'subaction': 'kc2_security_password_get_token',
                'prefix': 'kc2_customer_contract_details_extend_contract_',
                'type': '1',
                'ident': 'kc2_customer_contract_details_extend_contract_' + order_id
            }
            logger.debug(f"[步骤4] 请求参数: {data}")
            
            resp3 = self.session.post(url, headers=headers, data=data)
            resp3.raise_for_status()
            logger.debug(f"[步骤4] 响应状态: {resp3.status_code}")

            result = json.loads(resp3.text)
            if result.get('rs') != 'success':
                logger.error(f"❌ 获取 token 失败: {result.get('rs', 'unknown')}")
                if 'error' in result:
                    logger.error(f"错误信息: {result['error']}")
                return False
            
            token = result['token']['value']
            logger.info(f"✅ 步骤4完成: 获取到 token")
            time.sleep(3)

            logger.info("步骤5: 获取续期确认对话框...")
            data = {
                'sess_id': self.sess_id,
                'subaction': 'kc2_customer_contract_details_get_extend_contract_confirmation_dialog',
                'token': token
            }
       
            resp4 = self.session.post(url, headers=headers, data=data)
            resp4.raise_for_status()
            
            try:
                dialog_html = ""
                try:
                    result4 = json.loads(resp4.text)
                    if isinstance(result4, dict):
                        if 'html' in result4 and 'value' in result4['html']:
                            dialog_html = result4['html']['value']
                        elif 'value' in result4:
                             dialog_html = result4['value']
                except:
                    dialog_html = resp4.text
                
                match_subaction = re.search(r'name=["\']subaction["\']\s+value=["\']([^"\']+)["\']', dialog_html)
                next_subaction = match_subaction.group(1) if match_subaction else 'kc2_customer_contract_details_extend_contract_term'
                
                logger.debug(f"步骤6: 执行真正的续期 ({next_subaction})...")
                
                data_confirm = {}
                for match in re.finditer(r'<input[^>]+type=["\']hidden["\'][^>]*>', dialog_html, re.IGNORECASE):
                    input_tag = match.group(0)
                    name_match = re.search(r'name=["\']([^"\']+)["\']', input_tag)
                    value_match = re.search(r'value=["\']([^"\']+)["\']', input_tag)
                    if name_match and value_match:
                        data_confirm[name_match.group(1)] = value_match.group(1)

                if 'token' not in data_confirm:
                    token_match = re.search(r'name=["\']token["\']\s+value=["\']([^"\']+)["\']', dialog_html)
                    if token_match:
                         data_confirm['token'] = token_match.group(1)

                headers['Referer'] = 'https://support.euserv.com/index.iphp'
                
                time.sleep(2)
                resp5 = self.session.post(url, headers=headers, data=data_confirm)
                resp5.raise_for_status()
                
                html_lower = resp5.text.lower()
                if "error: token missing" in html_lower:
                     logger.error("❌ 续期失败: 服务器返回 'Error: token missing'")
                     return False

                success_keywords = ['successfully extended', 'erfolgreich', 'contract extended', 'verlängert', 'extension successful', 'contract has been extended']
                for keyword in success_keywords:
                    if keyword in html_lower:
                        logger.info(f"✅ 服务器 {order_id} 续期成功 (找到关键词: {keyword})")
                        return True

                logger.info(f"✅ 服务器 {order_id} 续期请求已提交 (假设成功，请检查邮件)")
                return True

            except Exception as e:
                logger.error(f"❌ 解析确认对话框或提交续期失败: {e}", exc_info=True)
                return False
        except Exception as e:
            logger.error(f"❌ 服务器 {order_id} 续期失败: {e}", exc_info=True)
            return False

def send_telegram(message: str, config: GlobalConfig):
    if not config.telegram_bot_token or not config.telegram_chat_id:
        logger.warning("⚠️ 未配置 Telegram，跳过通知")
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

def process_account(account_config: AccountConfig, global_config: GlobalConfig) -> Dict:
    result = {
        'email': account_config.email,
        'success': False,
        'servers': {},
        'renew_results': [],
        'error': None
    }
    
    try:
        euserv = EUserv(account_config)
        
        login_success = False
        for attempt in range(global_config.max_login_retries):
            if attempt > 0:
                logger.info(f"账号 {account_config.email} 第 {attempt + 1} 次登录尝试...")
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
            logger.info(f"检查服务器: {order_id}")
            if can_renew:
                logger.info(f"⏰ 服务器 {order_id} 可以续期，开始处理...")
                if euserv.renew_server(order_id):
                    result['renew_results'].append({
                        'order_id': order_id,
                        'success': True,
                        'message': f"✅ 服务器 {order_id} 续期成功"
                    })
                else:
                    result['renew_results'].append({
                        'order_id': order_id,
                        'success': False,
                        'message': f"❌ 服务器 {order_id} 续期失败"
                    })
                break
            else:
                logger.info(f"✓ 服务器 {order_id} 暂不需要续期（可续期日期: {can_renew_date}）")
        
        result['success'] = True
        
    except Exception as e:
        logger.error(f"处理账号 {account_config.email} 时发生异常: {e}", exc_info=True)
        result['error'] = str(e)
    
    return result

# ==================== 赛博自我修改机制核心函数 ====================
def update_github_workflow_cron(target_date: datetime.date) -> Tuple[bool, str]:
    """通过 GitHub API 自动修改 workflows 里的 cron 表达式"""
    token = os.getenv("PAT_WITH_WORKFLOW_SCOPE")
    repo = os.getenv("GITHUB_REPO")
    
    if not token or not repo:
        logger.warning("⚠️ 未配置 PAT_WITH_WORKFLOW_SCOPE 或 GITHUB_REPO，无法自动修改 Cron。")
        return False, "未配置 GitHub API 密钥"

    file_path = ".github/workflows/euserv续期.yml"
    api_url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    try:
        # 1. 获取当前文件信息
        resp = requests.get(api_url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        sha = data['sha']
        content = base64.b64decode(data['content']).decode('utf-8')

        # 2. 生成新的 cron 表达式 (UTC 0点，对应北京时间早8点)
        cron_expr = f"27 0 {target_date.day} {target_date.month} *"
        
        # 3. 精准替换文件中的 cron 内容
        new_content = re.sub(r"cron:\s*'.*?'", f"cron: '{cron_expr}'", content, count=1)
        
        if new_content == content:
            logger.info(f"📅 Cron 表达式已经是 '{cron_expr}'，无需更新。")
            return True, f"已是最新 {cron_expr}"

        # 4. 把更新提交给 GitHub API
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

def main():
    logger.info("=" * 60)
    logger.info("EUserv 多账号自动续期脚本（多线程版本 + 2FA防轰炸 + GitHub Cron 动态修改）")
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
                    'error': f"未预期的异常: {str(e)}"
                })
    
    logger.info("\n" + "=" * 60)
    logger.info("处理结果汇总")
    logger.info("=" * 60)
    
    message_parts = [f"<b>🔄 EUserv github 多账号续期报告</b>\n"]
    message_parts.append(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    message_parts.append(f"处理账号数: {len(all_results)}\n")
    
    for result in all_results:
        email = result['email']
        logger.info(f"\n账号: {email}")
        message_parts.append(f"\n<b>📧 账号: {email}</b>")
        
        if not result['success']:
            error_msg = result.get('error', '未知错误')
            logger.error(f"  ❌ 处理失败: {error_msg}")
            message_parts.append(f"  ❌ 处理失败: {error_msg}")
            continue
        
        servers = result.get('servers', {})
        logger.info(f"  服务器数量: {len(servers)}")
        
        renew_results = result.get('renew_results', [])
        if renew_results:
            logger.info(f"  续期操作: {len(renew_results)} 个")
            for renew_result in renew_results:
                logger.info(f"    {renew_result['message']}")
                message_parts.append(f"  {renew_result['message']}")
        else:
            logger.info("  ✓ 所有服务器均无需续期")
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
                    # 将类似 2026-07-25 的文本转换为 datetime 对象
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
    logger.info("执行完成")
    logger.info("=" * 60)

if __name__ == "__main__":
    main()
