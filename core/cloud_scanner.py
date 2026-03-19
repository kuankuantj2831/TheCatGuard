import requests
import hashlib
import time
import os
from .utils import get_logger
from . import config

logger = get_logger()

class CloudMalwareScanner:
    """VirusTotal云查杀引擎集成"""

    VT_API_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = None, cache_ttl: int = 86400):
        """
        Args:
            api_key: VirusTotal API密钥（免费版200次/天限制）
            cache_ttl: 缓存有效期（秒）
        """
        self.api_key = api_key or config.get('cloud_scanner.api_key', '')
        self.cache_ttl = cache_ttl
        self.cache = {}

    def scan_file_by_hash(self, file_hash: str):
        """
        通过SHA256哈希查询VirusTotal
        cost: 1个API调用
        返回格式: {
            'detected': bool,
            'detections': int,        # 检测到的反病毒引擎数
            'total': int,             # 总反病毒引擎数
            'engines': {...},         # 各引擎的检测结果
            'last_analysis_date': timestamp
        }
        """
        if not self.api_key:
            logger.warning("未配置VirusTotal API密钥，跳过云查杀")
            return {'detected': None, 'error': 'no_api_key'}

        # 检查缓存
        if file_hash in self.cache:
            cached, timestamp = self.cache[file_hash]
            if time.time() - timestamp < self.cache_ttl:
                return cached

        try:
            headers = {"x-apikey": self.api_key}
            url = f"{self.VT_API_URL}/files/{file_hash}"

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 404:
                # 哈希不在VirusTotal中（可能是新文件）
                result = {
                    'detected': False,
                    'detections': 0,
                    'total': 0,
                    'risk': 'unknown',
                    'status': 'not_found'
                }
            elif response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']

                # 关键逻辑：超过2个引擎检测 = 可疑
                result = {
                    'detected': stats['malicious'] > 0,
                    'detections': stats['malicious'],
                    'total': stats['malicious'] + stats['suspicious'] + stats['undetected'],
                    'risk': 'critical' if stats['malicious'] >= 3 else 'high' if stats['suspicious'] > 0 else 'low',
                    'engines': data['data']['attributes']['last_analysis_results']
                }
            else:
                result = {'error': response.status_code, 'detected': None}

            # 写入缓存
            self.cache[file_hash] = (result, time.time())
            return result

        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal查询失败: {e}")
            return {'error': str(e), 'detected': None}

    def scan_url(self, url: str):
        """
        扫描URL（检测钓鱼网站/恶意站点）
        """
        if not self.api_key:
            return {'risk': 'unknown', 'error': 'no_api_key'}

        try:
            import base64
            headers = {"x-apikey": self.api_key}

            # VirusTotal的URL扫描需要用base64编码
            url_id = base64.urlsafe_b64encode(f"{url}".encode()).decode().rstrip('=')
            url_endpoint = f"{self.VT_API_URL}/urls/{url_id}"

            response = requests.get(url_endpoint, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']

                return {
                    'risk': 'critical' if stats['malicious'] >= 2 else 'high' if stats['suspicious'] > 0 else 'safe',
                    'detections': stats['malicious'],
                    'category': data['data']['attributes'].get('categories', {})
                }
            return {'risk': 'unknown'}
        except Exception as e:
            logger.error(f"URL扫描失败: {e}")
            return {'error': str(e)}

def compute_sha256(file_path: str) -> str:
    """计算文件的SHA256哈希"""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"计算哈希失败 {file_path}: {e}")
        return ""