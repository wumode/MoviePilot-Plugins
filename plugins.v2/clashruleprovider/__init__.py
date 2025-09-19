import asyncio
import copy
import hashlib
import json
import math
import pytz
import re
import time
import yaml
from datetime import datetime, timedelta
from typing import Any, Final, Optional, List, Literal, Dict, Tuple, Union

import websockets
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import HTTPException, Request, status, Body, Response
from fastapi.responses import PlainTextResponse
from sse_starlette.sse import EventSourceResponse

from app import schemas
from app.core.cache import cached
from app.core.config import settings
from app.core.event import eventmanager, Event
from app.log import logger
from app.plugins import _PluginBase
from app.schemas.types import EventType
from app.schemas.types import NotificationType
from app.utils.http import RequestUtils, AsyncRequestUtils
from app.utils.ip import IpUtils

from .helper.configconverter import Converter
from .helper.clashruleparser import ClashRuleParser, Action, RuleType, ClashRule, MatchRule, LogicRule
from .helper.clashrulemanager import ClashRuleManager, RuleItem
from .helper.proxiesmanager import ProxyManager
from .helper.utilsprovider import UtilsProvider
from .models import ProxyBase, ProxyGroup, RuleProvider, Proxy, ProxyType
from .models.proxy.networkmixin import NetworkMixin
from .models.proxy.tlsmixin import TLSMixin


class ClashRuleProvider(_PluginBase):
    # 插件名称
    plugin_name = "Clash Rule Provider"
    # 插件描述
    plugin_desc = "随时为Clash添加一些额外的规则。"
    # 插件图标
    plugin_icon = "Mihomo_Meta_A.png"
    # 插件版本
    plugin_version = "2.0.1"
    # 插件作者
    plugin_author = "wumode"
    # 作者主页
    author_url = "https://github.com/wumode"
    # 插件配置项ID前缀
    plugin_config_prefix = "clashruleprovider_"
    # 加载顺序
    plugin_order = 99
    # 可使用的用户级别
    auth_level = 1

    # 插件配置
    # 启用插件
    _enabled = False
    _proxy = False
    _notify = False
    # 订阅链接配置
    _subscriptions_config: List[Dict[str, Any]] = []
    # MoviePilot URL
    _movie_pilot_url: str = ''
    _cron_string = ''
    _timeout = 10
    _retry_times = 3
    _filter_keywords = []
    _auto_update_subscriptions = True
    _ruleset_prefix: str = '📂<='
    _group_by_region: bool = False
    _group_by_country: bool = False
    _refresh_delay: int = 5
    _enable_acl4ssr: bool = False
    _dashboard_components: List[str] = []
    _clash_template: str = ''
    _hint_geo_dat: bool = False
    # Cloudflare 优选 IPs 可通过外部设置
    _best_cf_ip: List[str] = []
    _apikey: Optional[str] = None

    # 插件数据
    _rule_provider: Dict[str, Any] = {}
    _extra_rule_providers: Dict[str, Any] = {}
    _subscription_info = {}
    _ruleset_names: Dict[str, str] = {}
    _proxy_groups: List[Dict[str, Any]] = []
    _extra_proxies: List[Dict[str, Any]] = []
    _acl4ssr_providers: Dict[str, Any] = {}
    _acl4ssr_prefix: str = '🗂️=>'
    # 保存每个订阅文件的原始内容
    _clash_configs: Dict[str, Any] = {}
    _hosts: List[Dict[str, Any]] = []
    _clash_dashboards: List[Dict[str, str]] = []
    _active_dashboard: Optional[int] = None
    _overwritten_region_groups: Dict[str, Any] = {}
    _overwritten_proxies: Dict[str, Any] = {}

    # protected variables
    _top_rules_manager: ClashRuleManager = ClashRuleManager()
    _ruleset_rules_manager: ClashRuleManager = ClashRuleManager()
    _proxies_manager: ProxyManager = ProxyManager()
    _clash_template_dict: Optional[Dict[str, Any]] = None
    _scheduler: Optional[BackgroundScheduler] = None
    _geo_rules: Dict[str, List[str]] = {'geoip': [], 'geosite': []}
    _clash_dashboard_url: str = ''
    _clash_dashboard_secret: str = ''
    # 订阅链接
    _sub_links = []

    # constants
    DEFAULT_CLASH_CONF: Final[
        Dict[Literal['rules', 'rule-providers', 'proxies', 'proxy-groups', 'proxy-providers'], dict | list]] = {
        'rules': [], 'rule-providers': {}, 'proxies': [], 'proxy-groups': [], 'proxy-providers': {}
    }
    OVERWRITTEN_PROXIES_LIFETIME: Final[int] = 10

    def init_plugin(self, config: dict = None):
        self.stop_service()

        self._proxy_groups = self.get_data("proxy_groups") or []
        self._extra_proxies = self.get_data("extra_proxies") or []
        self._subscription_info = self.get_data("subscription_info") or {}
        self._rule_provider = self.get_data("rule_provider") or {}
        self._extra_rule_providers = self.get_data("extra_rule_providers") or {}
        self._ruleset_names = self.get_data("ruleset_names") or {}
        self._acl4ssr_providers = self.get_data("acl4ssr_providers") or {}
        self._clash_configs = self.get_data("clash_configs") or {}
        self._hosts = self.get_data("hosts") or []
        self._overwritten_region_groups = self.get_data("overwritten_region_groups") or {}
        self._overwritten_proxies = self.get_data("overwritten_proxies") or {}

        if config:
            self._enabled = config.get("enabled")
            self._proxy = config.get("proxy")
            self._notify = bool(config.get("notify"))
            sub_links = config.get("sub_links") or []
            self._subscriptions_config = config.get("subscriptions_config") or []
            self._subscriptions_config.extend(
                [{'url': url, 'rules': True, 'rule-providers': True, 'proxies': True, 'proxy-groups': True,
                  'proxy-providers': True}
                 for url in sub_links]
            )
            for sub in self._subscriptions_config:
                sub['url'] = sub['url'].strip()
            self._sub_links = [sub['url'] for sub in self._subscriptions_config if sub.get('url')]
            clash_dashboards = config.get("clash_dashboards")
            if clash_dashboards is None:
                clash_dashboards = [{'url': config.get('clash_dashboard_url') or '',
                                     'secret': config.get('clash_dashboard_secret') or ''}]
            self._clash_dashboards = []
            for clash_dashboard in clash_dashboards:
                url = (clash_dashboard.get("url") or '').rstrip('/')
                if not (url.startswith('http://') or url.startswith('https://')):
                    url = 'http://' + url
                self._clash_dashboards.append({'url': url, 'secret': clash_dashboard.get('secret') or ''})

            self._movie_pilot_url = config.get("movie_pilot_url") or ''
            if self._movie_pilot_url:
                self._movie_pilot_url = self._movie_pilot_url.rstrip('/')
            self._cron_string = config.get("cron_string") or '30 12 * * *'
            self._timeout = config.get("timeout")
            self._retry_times = config.get("retry_times") or 3
            self._filter_keywords = config.get("filter_keywords")
            self._ruleset_prefix = (config.get("ruleset_prefix") or "📂<=").strip()
            self._acl4ssr_prefix = (config.get("acl4ssr_prefix") or "🗂️=>").strip()
            self._auto_update_subscriptions = config.get("auto_update_subscriptions")
            self._group_by_region = config.get("group_by_region")
            self._group_by_country = config.get("group_by_country") or False
            self._refresh_delay = config.get("refresh_delay") or 5
            self._enable_acl4ssr = config.get("enable_acl4ssr") or False
            self._dashboard_components = config.get("dashboard_components") or []
            self._clash_template = config.get("clash_template") or ''
            self._hint_geo_dat = config.get("hint_geo_dat", False)
            self._best_cf_ip = config.get("best_cf_ip") or []
            self._active_dashboard = config.get("active_dashboard")
            if self._active_dashboard is None and self._clash_dashboards:
                self._active_dashboard = 0
            self._apikey = config.get("apikey")

        self.__update_config()
        self._clash_template_dict = {}
        if self._active_dashboard is not None and self._active_dashboard in range(len(self._clash_dashboards)):
            self._clash_dashboard_url = self._clash_dashboards[self._active_dashboard].get("url")
            self._clash_dashboard_secret = self._clash_dashboards[self._active_dashboard].get("secret")
        if self._enabled:
            self._proxies_manager.clear()
            self._top_rules_manager.clear()
            self._ruleset_rules_manager.clear()
            try:
                self._clash_template_dict = yaml.load(self._clash_template, Loader=yaml.SafeLoader) or {}
                if not isinstance(self._clash_template_dict, dict):
                    self._clash_template_dict = {}
                    logger.error(f"Invalid clash template yaml")
                # 规范配置模板
                self._clash_template_dict['proxies'] = self._clash_template_dict.get('proxies') or []
                for key, default in ClashRuleProvider.DEFAULT_CLASH_CONF.items():
                    self._clash_template_dict[key] = self._clash_template_dict.get(key) or copy.deepcopy(default)
                self._clash_template_dict['rules'] = self._clash_template_dict.get('rules') or []
            except yaml.YAMLError as exc:
                logger.error(f"Error loading clash template yaml: {exc}")

            self.__load_rules()
            self.__organize_and_save_rules()
            self.__load_proxies()
            # 清理不存在的 URL
            self._subscription_info = {url: self._subscription_info.get(url) or {} for url in self._sub_links}
            for _, sub_info in self._subscription_info.items():
                if 'enabled' not in sub_info:
                    sub_info['enabled'] = True
            self._clash_configs = {url: self._clash_configs[url] for url in self._sub_links if
                                   self._clash_configs.get(url)}
            for url, config in self._clash_configs.items():
                self.__add_proxies_to_manager(config.get('proxies', []),
                                              f"Sub:{UtilsProvider.get_url_domain(url)}-{abs(hash(url))}")
            self.__add_proxies_to_manager(self._clash_template_dict['proxies'], 'Template')
            self.__check_proxies_lifetime()
            self._scheduler = BackgroundScheduler(timezone=settings.TZ)
            self._scheduler.start()
            # 更新订阅
            self._scheduler.add_job(self.refresh_subscriptions, "date",
                                    run_date=datetime.now(tz=pytz.timezone(settings.TZ)) + timedelta(seconds=2))
            if self._hint_geo_dat:
                self._scheduler.add_job(self.__refresh_geo_dat, "date",
                                        run_date=datetime.now(tz=pytz.timezone(settings.TZ)) + timedelta(seconds=3))
            else:
                self._geo_rules = {'geoip': [], 'geosite': []}
            # 更新acl4ssr
            if self._enable_acl4ssr:
                self._scheduler.add_job(self.__refresh_acl4ssr, "date",
                                        run_date=datetime.now(tz=pytz.timezone(settings.TZ)) + timedelta(seconds=4))
            else:
                self._acl4ssr_providers = {}

    def get_state(self) -> bool:
        return self._enabled

    @staticmethod
    def get_command() -> List[Dict[str, Any]]:
        pass

    def get_api(self) -> List[Dict[str, Any]]:
        return [
            {
                "path": "/connectivity",
                "endpoint": self.test_connectivity,
                "methods": ["POST"],
                "auth": "bear",
                "summary": "测试连接",
                "description": "测试连接"
            },
            {
                "path": "/clash-outbound",
                "endpoint": self.get_clash_outbound,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "获取所有出站",
                "description": "获取所有出站"
            },
            {
                "path": "/status",
                "endpoint": self.get_status,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "插件状态",
                "description": "插件状态"
            },
            {
                "path": "/rules",
                "endpoint": self.get_rules,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "获取指定集合中的规则",
                "description": "获取指定集合中的规则"
            },
            {
                "path": "/reorder-rules",
                "endpoint": self.reorder_rules,
                "methods": ["PUT"],
                "auth": "bear",
                "summary": "重新排序两条规则",
                "description": "重新排序两条规则"
            },
            {
                "path": "/rule",
                "endpoint": self.update_rule,
                "methods": ["PUT"],
                "auth": "bear",
                "summary": "更新一条规则",
                "description": "更新一条规则"
            },
            {
                "path": "/rule",
                "endpoint": self.add_rule,
                "methods": ["POSt"],
                "auth": "bear",
                "summary": "添加一条规则",
                "description": "添加一条规则"
            },
            {
                "path": "/rule",
                "endpoint": self.delete_rule,
                "methods": ["DELETE"],
                "auth": "bear",
                "summary": "删除一条规则",
                "description": "删除一条规则"
            },
            {
                "path": "/subscription",
                "endpoint": self.refresh_subscription,
                "methods": ["PUT"],
                "auth": "bear",
                "summary": "更新订阅",
                "description": "更新订阅"
            },
            {
                "path": "/rule-providers",
                "endpoint": self.get_rule_providers,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "获取规则集合",
                "description": "获取规则集合"
            },
            {
                "path": "/extra-rule-provider",
                "endpoint": self.update_extra_rule_provider,
                "methods": ["POST"],
                "auth": "bear",
                "summary": "更新一个规则集合",
                "description": "更新一个规则集合"
            },
            {
                "path": "/extra-rule-provider",
                "endpoint": self.delete_extra_rule_provider,
                "methods": ["DELETE"],
                "auth": "bear",
                "summary": "删除一个规则集合",
                "description": "删除一个规则集合"
            },
            {
                "path": "/proxies",
                "endpoint": self.get_proxies,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "获取附加出站代理",
                "description": "获取附加出站代理"
            },
            {
                "path": "/proxies",
                "endpoint": self.delete_proxy,
                "methods": ["DELETE"],
                "auth": "bear",
                "summary": "删除一条出站代理",
                "description": "删除一条出站代理"
            },
            {
                "path": "/proxies",
                "endpoint": self.add_proxies,
                "methods": ["PUT"],
                "auth": "bear",
                "summary": "添加出站代理",
                "description": "添加出站代理"
            },
            {
                "path": "/proxies",
                "endpoint": self.update_proxy,
                "methods": ["POST"],
                "auth": "bear",
                "summary": "更新出站代理",
                "description": "更新出站代理"
            },
            {
                "path": "/proxy-groups",
                "endpoint": self.get_proxy_groups,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "获取代理组",
                "description": "获取代理组"
            },
            {
                "path": "/proxy-group",
                "endpoint": self.delete_proxy_group,
                "methods": ["DELETE"],
                "auth": "bear",
                "summary": "删除一个代理组",
                "description": "删除一个代理组"
            },
            {
                "path": "/proxy-group",
                "endpoint": self.add_proxy_group,
                "methods": ["POST"],
                "auth": "bear",
                "summary": "添加一个代理组",
                "description": "添加一个代理组"
            },
            {
                "path": "/proxy-group",
                "endpoint": self.update_proxy_group,
                "methods": ["PUT"],
                "auth": "bear",
                "summary": "更新一个代理组",
                "description": "更新一个代理组"
            },
            {
                "path": "/proxy-providers",
                "endpoint": self.get_proxy_providers,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "获取代理集合",
                "description": "获取代理集合"
            },
            {
                "path": "/ruleset",
                "endpoint": self.get_ruleset,
                "methods": ["GET"],
                "allow_anonymous": True if self._apikey else False,
                "summary": "获取规则集规则",
                "description": "获取规则集规则"
            },
            {
                "path": "/import",
                "endpoint": self.import_rules,
                "methods": ["POST"],
                "auth": "bear",
                "summary": "导入规则",
                "description": "导入规则"
            },
            {
                "path": "/hosts",
                "endpoint": self.get_hosts,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "获取 Hosts",
                "description": "获取 Hosts"
            },
            {
                "path": "/host",
                "endpoint": self.update_hosts,
                "methods": ["POST"],
                "auth": "bear",
                "summary": "更新 Host",
                "description": "更新 Host"
            },
            {
                "path": "/host",
                "endpoint": self.delete_host,
                "methods": ["DELETE"],
                "auth": "bear",
                "summary": "删除一条 Host",
                "description": "删除一条 Host"
            },
            {
                "path": "/subscription-info",
                "endpoint": self.update_subscription_info,
                "methods": ["POST"],
                "auth": "bear",
                "summary": "更新订阅信息",
                "description": "更新订阅信息"
            },
            {
                "path": "/config",
                "endpoint": self.get_clash_config,
                "methods": ["GET"],
                "allow_anonymous": True if self._apikey else False,
                "summary": "获取 Clash 配置",
                "description": "获取 Clash 配置"
            },
            {
                "path": "/clash/proxy/{path:path}",
                "auth": "bear",
                "endpoint": self.clash_proxy,
                "methods": ["GET"],
                "summary": "转发 Clash API 请求",
                "description": "转发 Clash API 请求"
            },
            {
                "path": "/clash/ws/{endpoint}",
                "endpoint": self.clash_websocket,
                "methods": ["GET"],
                "summary": "转发 Clash API Websocket 请求",
                "description": "转发 Clash API Websocket 请求",
                "allow_anonymous": True
            }
        ]

    def get_render_mode(self) -> Tuple[str, str]:
        """
        获取插件渲染模式
        :return: 1、渲染模式，支持：vue/vuetify，默认vuetify
        :return: 2、组件路径，默认 dist/assets
        """
        return "vue", "dist/assets"

    def get_form(self) -> Tuple[List[dict], Dict[str, Any]]:
        """
        拼装插件配置页面，需要返回两块数据：1、页面配置；2、数据结构
        """
        return [], {}

    def get_dashboard_meta(self) -> Optional[List[Dict[str, str]]]:
        components = [
            {
                "key": "clash_info",
                "name": "Clash Info"
            },
            {
                "key": "traffic_stats",
                "name": "Traffic Stats"
            }
        ]
        return [component for component in components if component.get("name") in self._dashboard_components]

    def get_dashboard(self, key: str, **kwargs) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], List[dict]]]:
        """
        获取插件仪表盘页面，需要返回：1、仪表板col配置字典；2、全局配置（自动刷新等）；3、仪表板页面元素配置json（含数据）
        1、col配置参考：
        {
            "cols": 12, "md": 6
        }
        2、全局配置参考：
        {
            "refresh": 10, // 自动刷新时间，单位秒
            "border": True, // 是否显示边框，默认True，为False时取消组件边框和边距，由插件自行控制
            "title": "组件标题", // 组件标题，如有将显示该标题，否则显示插件名称
            "subtitle": "组件子标题", // 组件子标题，缺省时不展示子标题
        }
        3、页面配置使用Vuetify组件拼装，参考：https://vuetifyjs.com/

        kwargs参数可获取的值：1、user_agent：浏览器UA

        :param key: 仪表盘key，根据指定的key返回相应的仪表盘数据，缺省时返回一个固定的仪表盘数据（兼容旧版）
        """
        clash_available = bool(self._clash_dashboard_url and self._clash_dashboard_secret)
        components = {'clash_info': {'title': 'Clash Info', 'md': 4},
                      'traffic_stats': {'title': 'Traffic Stats', 'md': 8}}
        col_config = {'cols': 12, 'md': components.get(key, {}).get('md', 4)}
        global_config = {
            'title': components.get(key, {}).get('title', 'Clash Info'),
            'border': True,
            'clash_available': clash_available,
            'secret': self._clash_dashboard_secret,
        }
        return col_config, global_config, []

    def get_page(self) -> List[dict]:
        return []

    def stop_service(self):
        """
        退出插件
        """
        if self._scheduler:
            try:
                self._scheduler.remove_all_jobs()
                if self._scheduler.running:
                    self._scheduler.shutdown()
                self._scheduler = None
            except Exception as e:
                logger.error(f"退出插件失败：{e}")

    def get_service(self) -> List[Dict[str, Any]]:
        if self.get_state() and self._auto_update_subscriptions and self._sub_links:
            return [{
                "id": "ClashRuleProvider",
                "name": "定时更新订阅",
                "trigger": CronTrigger.from_crontab(self._cron_string),
                "func": self.refresh_subscription_service,
                "kwargs": {}
            }]
        return []

    def __update_config(self):
        config = {
            'enabled': self._enabled,
            'proxy': self._proxy,
            'notify': self._notify,
            'subscriptions_config': self._subscriptions_config,
            'clash_dashboards': self._clash_dashboards,
            'movie_pilot_url': self._movie_pilot_url,
            'cron_string': self._cron_string,
            'timeout': self._timeout,
            'retry_times': self._retry_times,
            'filter_keywords': self._filter_keywords,
            'auto_update_subscriptions': self._auto_update_subscriptions,
            'ruleset_prefix': self._ruleset_prefix,
            'acl4ssr_prefix': self._acl4ssr_prefix,
            'group_by_region': self._group_by_region,
            'group_by_country': self._group_by_country,
            'refresh_delay': self._refresh_delay,
            'enable_acl4ssr': self._enable_acl4ssr,
            'dashboard_components': self._dashboard_components,
            'clash_template': self._clash_template,
            'hint_geo_dat': self._hint_geo_dat,
            'best_cf_ip': self._best_cf_ip,
            'active_dashboard': self._active_dashboard,
            'apikey': self._apikey
        }
        self.update_config(config)

    def update_best_cf_ip(self, ips: List[str]):
        """
        通过深拷贝更新 Cloudflare 优选 IPs
        :param ips: Best Cloudflare IPs
        """
        self._best_cf_ip = [*ips]
        config = self.get_config()
        config['best_cf_ip'] = self._best_cf_ip
        self.update_config(config)

    def __check_proxies_lifetime(self):
        for proxy in self._proxies_manager:
            proxy_name = proxy.proxy.name
            if proxy_name in self._overwritten_proxies:
                self._overwritten_proxies[proxy_name]['lifetime'] = ClashRuleProvider.OVERWRITTEN_PROXIES_LIFETIME
        outdated_proxies = []
        for proxy_name in self._overwritten_proxies:
            if proxy_name not in self._proxies_manager:
                self._overwritten_proxies[proxy_name]['lifetime'] = self._overwritten_proxies[proxy_name].get(
                    'lifetime', ClashRuleProvider.OVERWRITTEN_PROXIES_LIFETIME) - 1
                if self._overwritten_proxies[proxy_name]['lifetime'] < 0:
                    outdated_proxies.append(proxy_name)
        for proxy_name in outdated_proxies:
            del self._overwritten_proxies[proxy_name]
        self.save_data('overwritten_proxies', self._overwritten_proxies)

    def __load_proxies(self):
        proxies = self.get_data("proxies") or []
        initial_len = len(proxies)
        proxies.extend(self._extra_proxies)
        invalid_proxies = []
        for proxy in proxies:
            try:
                if isinstance(proxy, dict):
                    proxy = UtilsProvider.filter_empty(proxy, empty=['', None])
                    self._proxies_manager.add_proxy_dict(proxy, remark='Manual')
                if isinstance(proxy, str):
                    proxy_dict = Converter.convert_line(proxy)
                    if proxy_dict:
                        self._proxies_manager.add_proxy_dict(proxy_dict, remark='Manual', raw=proxy)
            except Exception as e:
                logger.error(f"Failed to load proxy {proxy}: {e}")
                invalid_proxies.append(proxy)
        if len(self._extra_proxies) != len(invalid_proxies):
            self._extra_proxies = invalid_proxies
            self.save_data('extra_proxies', self._extra_proxies)
        if len(self._proxies_manager) > initial_len:
            self.__save_proxies()

    def __save_proxies(self):
        proxies = self._proxies_manager.export_raw(condition=lambda proxy: proxy.remark == 'Manual')
        self.save_data('proxies', proxies)

    def __load_rules(self):
        def process_rules(raw_rules, manager, key):
            raw_rules = raw_rules or []
            rules = [self.__upgrade_rule(r) if isinstance(r, str) else r for r in raw_rules]
            manager.import_rules(rules)
            if any(isinstance(r, str) for r in raw_rules):
                self.save_data(key, manager.export_rules())

        process_rules(self.get_data("top_rules"), self._top_rules_manager, "top_rules")
        process_rules(self.get_data("ruleset_rules"), self._ruleset_rules_manager, "ruleset_rules")

    def __upgrade_rule(self, rule_string: str) -> Dict[str, str]:
        rule = ClashRuleParser.parse_rule_line(rule_string)
        remark = 'Manual'
        if isinstance(rule, ClashRule) and rule.rule_type == RuleType.RULE_SET and rule.payload.startswith(
                self._ruleset_prefix):
            remark = 'Auto'
        return {'rule': rule_string, 'remark': remark}

    async def clash_websocket(self, request: Request, endpoint: str, secret: str):
        if secret != self._clash_dashboard_secret:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Secret 校验不通过"
            )
        if endpoint not in ['traffic', 'connections', 'memory']:
            raise HTTPException(status_code=400, detail="Invalid endpoint")
        queue = asyncio.Queue()
        ws_base = self._clash_dashboard_url.replace('http://', 'ws://').replace('https://', 'wss://')
        url = f"{ws_base}/{endpoint}?token={self._clash_dashboard_secret}"

        async def clash_ws_listener():
            try:
                async with websockets.connect(url, ping_interval=None) as ws:
                    async for message in ws:
                        data = json.loads(message)
                        await queue.put(data)
            except Exception as e:
                await queue.put({"error": str(e)})

        listener_task = asyncio.create_task(clash_ws_listener())

        async def event_generator():
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        data = await queue.get()
                        yield {
                            'event': endpoint,
                            'data': json.dumps(data)
                        }
                    except asyncio.CancelledError:
                        break
            finally:
                listener_task.cancel()  # 停止与 Clash 的连接

        return EventSourceResponse(event_generator())

    async def fetch_clash_data(self, endpoint: str) -> Dict:
        clash_headers = {"Authorization": f"Bearer {self._clash_dashboard_secret}"}
        url = f"{self._clash_dashboard_url}/{endpoint}"
        response = await AsyncRequestUtils().get_json(url, headers=clash_headers, timeout=10)
        if response is None:
            raise HTTPException(status_code=502, detail=f"Failed to fetch {endpoint}")
        return response

    async def clash_proxy(self, path: str) -> Dict:
        return await self.fetch_clash_data(path)

    async def test_connectivity(self, params: Dict[str, Any]) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message="")
        if params.get('clash_dashboards') is None or not params.get('sub_links'):
            return schemas.Response(success=True, message="Missing params")

        tasks = []
        for clash_dashboard in params['clash_dashboards']:
            url = clash_dashboard.get('url') or ''
            secret = clash_dashboard.get('secret') or ''
            tasks.append(asyncio.create_task(ClashRuleProvider.async_fetch_clash_version(url, secret)))
        results = await asyncio.gather(*tasks)
        for i, result in enumerate(results):
            if not result:
                return schemas.Response(success=False,
                                        message=f"无法连接到 Clash {params['clash_dashboards'][i].get('url')}")
        for sub_link in (params.get('sub_links') or []):
            ret = await AsyncRequestUtils(accept_type="text/html",
                                          proxies=settings.PROXY if self._proxy else None
                                          ).get(sub_link)
            if ret is None:
                return schemas.Response(success=False, message=f"无法获取 {sub_link}")
        return schemas.Response(success=True, message="测试连接成功")

    @staticmethod
    async def async_fetch_clash_version(url: str, secret: str) -> Optional[str]:
        url = url.rstrip('/')
        clash_version_url = f"{url}/version"
        ret = await AsyncRequestUtils(accept_type="application/json",
                                      headers={"authorization": f"Bearer {secret}"},
                                      timeout=5
                                      ).get_json(clash_version_url)
        return ret

    def get_ruleset(self, name: str, apikey: str) -> Response:
        _apikey = self._apikey or settings.API_TOKEN
        if apikey != _apikey:
            raise HTTPException(status_code=403, detail="Invalid API Key")
        ruleset_name = self._ruleset_names.get(name)
        if ruleset_name is None:
            raise HTTPException(status_code=404, detail=f"Ruleset '{name}' not found")

        rules = self.__get_ruleset(ruleset_name)
        res = yaml.dump({"payload": rules}, allow_unicode=True)

        return PlainTextResponse(content=res, media_type="application/x-yaml")

    def get_clash_outbound(self) -> schemas.Response:
        outbound = self.clash_outbound()
        return schemas.Response(success=True, data={"outbound": outbound})

    def get_status(self) -> schemas.Response:
        data = {"state": self._enabled,
                "ruleset_prefix": self._ruleset_prefix,
                "best_cf_ip": self._best_cf_ip,
                "geoRules": self._geo_rules,
                "subscription_info": self._subscription_info,
                "sub_url": f"{self._movie_pilot_url}/api/v1/plugin/ClashRuleProvider/config?"
                           f"apikey={self._apikey or settings.API_TOKEN}"}
        return schemas.Response(success=True, data=data)

    def update_subscription_info(self, params: Dict[str, Any]) -> schemas.Response:
        url = params.get('url')
        field = params.get('field')
        if 'value' not in params or url not in self._subscription_info or field not in ['name', 'enabled']:
            return schemas.Response(success=False, message="Missing params")
        value = params.get('value')
        self._subscription_info[url][field] = value
        self.save_data('subscription_info', self._subscription_info)
        return schemas.Response(success=True)

    def get_clash_config(self, apikey: str, request: Request):
        _apikey = self._apikey or settings.API_TOKEN
        if apikey != _apikey:
            raise HTTPException(status_code=403, detail="Invalid API Key")
        logger.info(f"{request.client.host} 正在获取配置")
        config = self.clash_config()
        if not config:
            return schemas.Response(success=False, message="配置不可用")
        res = yaml.dump(config, allow_unicode=True, sort_keys=False)
        sub_info = {'upload': 0, 'download': 0, 'total': 0, 'expire': 0}
        for info in self._subscription_info.values():
            if not info:
                continue
            sub_info['upload'] += info.get('upload', 0)
            sub_info['download'] += info.get('download', 0)
            sub_info['total'] += info.get('total', 0)
            sub_info['expire'] = max(sub_info['expire'], info.get('expire') or 0)
        headers = {'Subscription-Userinfo': f'upload={sub_info.get("upload", 0)}; '
                                            f'download={sub_info.get("download", 0)}; '
                                            f'total={sub_info.get("total", 0)}; '
                                            f'expire={sub_info.get("expire", 0)}'}
        return Response(headers=headers, content=res, media_type="text/yaml")

    def get_hosts(self) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=True, data={'hosts': []})
        return schemas.Response(success=True, data={'hosts': self._hosts})

    def update_hosts(self, params: dict = Body(...)) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message='')
        domain = params.get('domain')
        if not domain:
            return schemas.Response(success=False, message=f"Invalid param: domain={domain}")
        # Search for the host with the same domain
        for i, host in enumerate(self._hosts):
            if host.get('domain') == domain:
                # Update the existing host
                self._hosts[i] = {**host, **params.get('value', {})}
                self.save_data('hosts', self._hosts)
                return schemas.Response(success=True, message=f'Host for domain {domain} updated successfully.')

        new_host = params.get('value', {})
        if not new_host.get('domain'):
            return schemas.Response(success=False, message=f"Invalid param: value={new_host}")
        self._hosts.append(new_host)
        self.save_data('hosts', self._hosts)

        return schemas.Response(success=True, message=f"New host for domain {domain} added successfully.")

    def delete_host(self, params: dict = Body(...)) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message='Host deletion is disabled.')

        domain = params.get('domain')
        if not domain:
            return schemas.Response(success=False, message=f"Invalid param: domain={domain}")

        original_hosts_length = len(self._hosts)
        self._hosts = [host for host in self._hosts if host.get('domain') != domain]
        self.save_data('hosts', self._hosts)

        if len(self._hosts) < original_hosts_length:
            return schemas.Response(success=True, message=f'Host for domain {domain} deleted successfully.')
        else:
            return schemas.Response(success=False, message=f'Host for domain {domain} not found.')

    def get_rules(self, rule_type: str) -> schemas.Response:
        if rule_type == 'ruleset':
            return schemas.Response(success=True, data={'rules': self._ruleset_rules_manager.to_list()})
        return schemas.Response(success=True, data={'rules': self._top_rules_manager.to_list()})

    def delete_rule(self, params: dict = Body(...)) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message='')
        priority = params.get('priority', -1)
        if params.get('type') == 'ruleset':
            res = self._ruleset_rules_manager.remove_rule_at_priority(priority)
            if res:
                rule = res.rule
                self.__add_notification_job(
                    [f"{self._ruleset_prefix}{rule.action.value if isinstance(rule.action, Action) else rule.action}"])
        else:
            self._top_rules_manager.remove_rule_at_priority(priority)
        self.__organize_and_save_rules()
        return schemas.Response(success=True)

    def import_rules(self, params: Dict[str, Any]) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message='')
        rules: List[str] = []
        if params.get('type') == 'YAML':
            try:
                imported_rules = yaml.load(params["payload"], Loader=yaml.SafeLoader)
                if not isinstance(imported_rules, dict):
                    return schemas.Response(success=False, message='Invalid input')
                rules = imported_rules.get("rules", [])
            except yaml.YAMLError as err:
                return schemas.Response(success=False, message=f'YAML error: {err}')
        self.append_top_rules(rules)
        return schemas.Response(success=True)

    def reorder_rules(self, params: Dict[str, Any]) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message='')
        moved_priority = params.get('moved_priority')
        target_priority = params.get('target_priority')
        try:
            if params.get('type') == 'ruleset':
                self._ruleset_rules_manager.reorder_rules(moved_priority, target_priority)
                self.__add_notification_job([f"{self._ruleset_prefix}{params.get('rule_data').get('action')}"])
            else:
                self._top_rules_manager.reorder_rules(moved_priority, target_priority)
            self.__organize_and_save_rules()
        except Exception as e:
            return schemas.Response(success=False, message=str(e))
        return schemas.Response(success=True)

    def update_rule(self, params: Dict[str, Any]) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message='')
        try:
            rule_data = params['rule_data']
            dst_priority = rule_data['priority']
            src_priority = params.get('priority', dst_priority)
            clash_rule = ClashRuleParser.parse_rule_dict(rule_data)
            if not clash_rule:
                logger.error(f"Failed to update rule at priority {src_priority}. Invalid clash rule: {rule_data!r}")
                return schemas.Response(success=False,
                                        message=f"Failed to update rule at priority {src_priority}. "
                                                f"Invalid clash rule: {rule_data!r}")

            if params.get('type') == 'ruleset':
                original_rule = self._ruleset_rules_manager.get_rule_at_priority(src_priority)
                rule_item = RuleItem(rule=clash_rule, remark=original_rule.remark)
                res = self._ruleset_rules_manager.update_rule_at_priority(rule_item, src_priority, dst_priority)
                if res:
                    ruleset_to_notify = [f"{self._ruleset_prefix}{clash_rule.action}"]
                    if rule_data.get('action') != original_rule.rule.action:
                        ruleset_to_notify.append(f"{self._ruleset_prefix}{original_rule.rule.action}")
                    self.__add_notification_job(ruleset_to_notify)
            else:
                original_rule = self._top_rules_manager.get_rule_at_priority(src_priority)
                rule_item = RuleItem(rule=clash_rule, remark=original_rule.remark)
                res = self._top_rules_manager.update_rule_at_priority(rule_item, src_priority, dst_priority)
        except Exception as e:
            return schemas.Response(success=False, message=str(e))
        self.__organize_and_save_rules()
        return schemas.Response(success=bool(res), message='')

    def add_rule(self, params: Dict[str, Any]) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message='')
        try:
            rule_data = params['rule_data']
            priority = rule_data.get('priority', 0)
            clash_rule = ClashRuleParser.parse_rule_dict(rule_data)
            if not clash_rule:
                logger.warn(f"无效的输入规则: {params.get('rule_data')}")
                return schemas.Response(success=False, message=f"无效的输入规则: {params.get('rule_data')}")
            rule_item = RuleItem(rule=clash_rule, remark='Manual')
            if params.get('type') == 'ruleset':
                self._ruleset_rules_manager.insert_rule_at_priority(rule_item, priority)
                self.__add_notification_job([f"{self._ruleset_prefix}{clash_rule.action}", ])
            else:
                self._top_rules_manager.insert_rule_at_priority(rule_item, priority)
        except Exception as e:
            return schemas.Response(success=False, message=str(e))
        self.__organize_and_save_rules()
        return schemas.Response(success=True)

    def refresh_subscription(self, params: Dict[str, Any]):
        if not self._enabled:
            return schemas.Response(success=False, message="")
        url = params.get('url')
        if not url:
            return schemas.Response(success=False, message="Missing params")
        sub_conf = next(conf for _, conf in enumerate(self._subscriptions_config) if conf['url'] == url)
        config, info = self.__get_subscription(url, sub_conf)
        if not config:
            return schemas.Response(success=False, message=f"订阅链接 {url} 更新失败")
        self._clash_configs[url] = config
        remark = f"Sub:{UtilsProvider.get_url_domain(url)}-{abs(hash(url))}"
        self._proxies_manager.remove_proxies_by_condition(lambda p: p.remark == remark)
        self.__add_proxies_to_manager(config.get("proxies", []), remark)
        self._subscription_info[url] = {**info, 'enabled': self._subscription_info.get(url, {}).get('enabled', False)}
        self.save_data('clash_configs', self._clash_configs)
        self.save_data('subscription_info', self._subscription_info)
        return schemas.Response(success=True, message='订阅更新成功')

    def get_rule_providers(self) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=True, data=[])
        return schemas.Response(success=True, data=self.rule_providers())

    def update_extra_rule_provider(self, params: Dict[str, Any]) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message='')
        name = params.get('name')
        new_value = params.get('value')
        new_name = new_value.get('name')
        if not name or not new_name:
            return schemas.Response(success=False, message="Missing param: name")
        item = {}
        for key, value in new_value.items():
            if key == 'name' or value is None:
                continue
            if key == 'payload' and params.get('type') != 'inline':
                continue
            if value == '' or value is None:
                continue
            item[key] = value
        try:
            rule_provider = RuleProvider.parse_obj(item)
            if rule_provider.type == 'inline' and rule_provider.behavior == 'classical':
                for rule in rule_provider.payload:
                    clash_rule = ClashRuleParser.parse_rule_line(f"{rule},DIRECT")
                    if not clash_rule:
                        raise ValueError(f"Invalid clash_rule: {rule}")
        except Exception as e:
            error_message = f"Failed to save rule provider: {repr(e)}"
            logger.error(error_message)
            return schemas.Response(success=False, message=str(error_message))
        if name != new_name:
            self._extra_rule_providers.pop(name, None)
        self._extra_rule_providers[new_name] = item
        self.save_data('extra_rule_providers', self._extra_rule_providers)
        return schemas.Response(success=True)

    def delete_extra_rule_provider(self, params: Dict[str, Any]) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message='')
        name = params.get('name')
        if not name:
            return schemas.Response(success=False, message="Missing param: name")
        self._extra_rule_providers.pop(name, None)
        self.save_data('extra_rule_providers', self._extra_rule_providers)
        return schemas.Response(success=True)

    def get_proxy_groups(self) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=True, data={'proxy_groups': []})
        proxy_groups = []
        sub = self.dict_from_sub_conf('proxy-groups')
        hostnames = [UtilsProvider.get_url_domain(url) or '' for url in sub]
        sub_proxy_groups = sub.values()
        sources = ('Manual', 'Template', *hostnames, 'Region')
        groups = (self._proxy_groups, self._clash_template_dict.get('proxy-groups', []),
                  *sub_proxy_groups, self.proxy_groups_by_region())
        for i, group in enumerate(groups):
            for proxy_group in group:
                proxy_group_copy = copy.deepcopy(proxy_group)
                proxy_group_copy['source'] = sources[i]
                proxy_groups.append(proxy_group_copy)
        return schemas.Response(success=True, data={'proxy_groups': proxy_groups})

    def get_proxy_providers(self) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=True, data={'proxy_providers': {}})
        proxy_providers = self.all_proxy_providers()
        return schemas.Response(success=True, data={'proxy_providers': proxy_providers})

    def get_proxies(self) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=True, data={'proxies': []})
        proxies = self.proxies(regex='^Manual$', flat=False)
        proxies.extend(self.proxies(regex='^Template$', flat=False))
        proxies.extend(self.proxies(regex='^Sub:', flat=False))
        ret = []
        for proxy in proxies:
            remark = proxy['remark']
            i = remark.rfind('-')
            source = remark[remark.rfind(':') + 1:(len(remark) if i == -1 else i)]
            if isinstance(proxy['raw'], str):
                proxy_link = proxy['raw']
            else:
                try:
                    proxy_link = Converter.convert_to_share_link(proxy['proxy'])
                except Exception as e:
                    logger.warn(f"Failed to convert proxy link: {repr(e)}")
                    proxy_link = None
            proxy['proxy']['source'] = source
            proxy['proxy']['v2ray_link'] = proxy_link
            proxy['proxy']['overwritten'] = proxy['proxy']['name'] in self._overwritten_proxies
            ret.append(proxy['proxy'])
        ret.extend([{'source': 'Invalid', 'v2ray_link': None, **proxy} for proxy in self._extra_proxies])
        return schemas.Response(success=True, data={'proxies': ret})

    def add_proxies(self, params: Dict[str, Any]):
        if not self._enabled:
            return schemas.Response(success=False, message='')
        extra_proxies: List = []
        if params.get('type') == 'YAML':
            try:
                imported_proxies = yaml.load(params["payload"], Loader=yaml.SafeLoader)
                if not imported_proxies or not isinstance(imported_proxies, dict):
                    return schemas.Response(success=False, message=f"Invalid input")
                if 'proxies' not in imported_proxies:
                    return schemas.Response(success=False, message=f"No field 'proxies' found")
                extra_proxies = [{'proxy': proxy, 'raw': None} for proxy in imported_proxies.get("proxies", [])]
            except Exception as err:
                return schemas.Response(success=False, message=f'YAML error: {err}')
        elif params.get('type') == 'LINK':
            try:
                links = params['payload'].strip().splitlines()
                names = {}
                for link in links:
                    proxy = Converter.convert_line(link, names, skip_exception=True)
                    if proxy:
                        extra_proxies.append({'proxy': proxy, 'raw': None})
            except Exception as err:
                return schemas.Response(success=False, message=f'LINK error: {err}')
        if not extra_proxies:
            return schemas.Response(success=False, message='无可用节点')
        result = True
        message = ''
        success = 0
        for proxy_item in extra_proxies:
            try:
                self._proxies_manager.add_proxy_dict(proxy_item['proxy'], 'Manual', raw=proxy_item['raw'])
                success += 1
            except Exception as err:
                result = False
                message += f"{err}\n"
        message = f"导入 {success}/{len(extra_proxies)} 个代理节点. \n{message}"
        self.__save_proxies()
        return schemas.Response(success=result, message=message)

    def delete_proxy(self, params: dict = Body(...)) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message='')
        name = params.get('name')
        extra_proxies = [p for p in self._extra_proxies if p.get('name') != name]
        if len(extra_proxies) != self._extra_proxies:
            self._extra_proxies = extra_proxies
            self.save_data('extra_proxies', self._extra_proxies)
        self._proxies_manager.remove_proxy(name)
        self.__save_proxies()
        return schemas.Response(success=True)

    def add_proxy_group(self, params: Dict[str, Any]) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message='')
        if 'proxy_group' not in params or params['proxy_group'] is None:
            return schemas.Response(success=False, message="Missing params")
        item = params['proxy_group']
        if not item.get('name') or any(x.get('name') == item.get('name') for x in self._proxy_groups):
            return schemas.Response(success=False, message=f"The proxy group name {item.get('name')} already exists")
        try:
            proxy_group = ProxyGroup.parse_obj(item)
        except Exception as e:
            error_message = f"Failed to parse proxy group: Invalid data={item}, error={repr(e)}"
            logger.error(error_message)
            return schemas.Response(success=False, message=str(error_message))

        self._proxy_groups.append(proxy_group.dict(by_alias=True, exclude_none=True))
        self.save_data('proxy_groups', self._proxy_groups)
        return schemas.Response(success=True)

    def update_proxy(self, params: Dict[str, Any]) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message='')
        proxy_dict = params.get('proxy', {})
        previous_name = params.get('name')
        if previous_name not in self._proxies_manager:
            return schemas.Response(success=False, message=f"The proxy name {previous_name} does not exist")
        if proxy_dict.get('rescind'):
            self.remove_overwritten_proxy(previous_name)
            return schemas.Response(success=True)
        try:
            Proxy.parse_obj(proxy_dict)
            if  proxy_dict['name'] != previous_name:
                return schemas.Response(success=False, message=f"Proxy name is not allowed to be overwritten")
            self.overwrite_proxy(proxy_dict)
        except Exception as e:
            logger.error(f"Failed to overwrite proxy: Invalid data={proxy_dict}, error={repr(e)}")
            return schemas.Response(success=False,
                                    message=f"Failed to overwrite proxy: Invalid data={proxy_dict}, error={repr(e)}")
        return schemas.Response(success=True)

    def update_proxy_group(self, params: Dict[str, Any]) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message='')
        proxy_group_dict = params.get('proxy_group', {})
        previous_name = params.get('name')
        region_groups = {g['name'] for g in self.proxy_groups_by_region()}

        # 更新区域分组覆写配置
        if previous_name in region_groups:
            try:
                self.overwrite_region_group(proxy_group_dict)
            except Exception as e:
                logger.error(f"Failed to overwrite proxy group: Invalid data={proxy_group_dict}, error={repr(e)}")
                return schemas.Response(success=False,
                                        message=f"Failed to overwrite proxy group: "
                                                f"Invalid data={proxy_group_dict}, error={repr(e)}")
            return schemas.Response(success=True)
        if not previous_name or not proxy_group_dict:
            return schemas.Response(success=False, message='Invalid params')

        try:
            proxy_group = ProxyGroup.parse_obj(proxy_group_dict)
        except Exception as e:
            error_message = f"Failed to parse proxy group: Invalid data={proxy_group_dict}, error={repr(e)}"
            logger.error(error_message)
            return schemas.Response(success=False, message=str(error_message))
        index = next((i for i, x in enumerate(self._proxy_groups) if x.get('name') == previous_name), None)
        if index is None:
            return schemas.Response(success=False, message=f"Proxy group {previous_name!r} does not exist")
        # whether new name exists
        new_name_index = next((i for i, x in enumerate(self._proxy_groups) \
                               if x.get('name') == proxy_group_dict['name']), None)
        if new_name_index and new_name_index != index:
            return schemas.Response(success=False,
                                    message=f"The proxy group name {proxy_group_dict['name']} already exists")

        self._proxy_groups[index] = proxy_group.dict(by_alias=True, exclude_none=True)
        self.save_data('proxy_groups', self._proxy_groups)
        return schemas.Response(success=True)

    def delete_proxy_group(self, params: dict = Body(...)) -> schemas.Response:
        if not self._enabled:
            return schemas.Response(success=False, message='')
        name = params.get('name')
        self._proxy_groups = [item for item in self._proxy_groups if item.get('name') != name]
        self.save_data('proxy_groups', self._proxy_groups)
        return schemas.Response(success=True)

    def overwrite_proxy(self, proxy: Dict[str, Any]):
        proxy_base = ProxyBase.parse_obj(proxy)
        tls = TLSMixin.parse_obj(proxy)
        network = NetworkMixin.parse_obj(proxy)
        overwrite_config = {'base': proxy_base.dict(by_alias=True, exclude_none=True),
                            'tls': tls.dict(by_alias=True, exclude_none=True),
                            'network': network.dict(by_alias=True, exclude_none=True),
                            'lifetime': ClashRuleProvider.OVERWRITTEN_PROXIES_LIFETIME}
        self._overwritten_proxies[proxy_base.name] = overwrite_config
        self.save_data('overwritten_proxies', self._overwritten_proxies)

    def remove_overwritten_proxy(self, proxy_name: str):
        self._overwritten_proxies.pop(proxy_name, None)
        self.save_data('overwritten_proxies', self._overwritten_proxies)

    def overwrite_region_group(self, proxy_group: Dict[str, Any]):
        region_group = ProxyGroup.parse_obj(proxy_group)
        overwrite_config = {k: v for k, v in region_group.dict(by_alias=True, exclude_none=True).items() if
                            k not in {'name', 'proxies'}}
        self._overwritten_region_groups[proxy_group['name']] = overwrite_config
        self.__group_by_region.cache_clear()
        self.save_data('overwritten_region_groups', self._overwritten_region_groups)

    def clash_outbound(self) -> List[Dict[str, Any]]:
        outbound = [{'name': proxy_group.get("name")} for proxy_group in self.value_from_sub_conf('proxy-groups')]
        if self._clash_template_dict:
            if 'proxy-groups' in self._clash_template_dict:
                outbound.extend(self._clash_template_dict.get('proxy-groups') or [])
        if self._group_by_region:
            outbound.extend([{'name': proxy_group.get("name")} for proxy_group in self.proxy_groups_by_region()])
        outbound.extend([{'name': proxy_group.get("name")} for proxy_group in self._proxy_groups])
        outbound.extend([{'name': proxy_name} for proxy_name in self._proxies_manager.proxy_names()])
        return outbound

    def rule_providers(self) -> List[Dict[str, Any]]:
        rule_providers = []
        sub = self.dict_from_sub_conf('rule-providers')
        hostnames = [UtilsProvider.get_url_domain(url) for url in sub]
        sub_rule_providers = sub.values()
        provider_sources = (self._extra_rule_providers,
                            *sub_rule_providers,
                            self._clash_template_dict.get('rule-providers', {}),
                            self._acl4ssr_providers)
        source_names = ('Manual', *hostnames, 'Template', 'Auto', 'Acl4ssr')
        for i, provider in enumerate(provider_sources):
            for name, value in provider.items():
                rule_provider = copy.deepcopy(value)
                rule_provider['name'] = name
                rule_provider['source'] = source_names[i]
                rule_providers.append(rule_provider)
        return rule_providers

    def __organize_and_save_rules(self):
        self.__insert_ruleset()
        self.save_data('top_rules', self._top_rules_manager.export_rules())
        self.save_data('ruleset_rules', self._ruleset_rules_manager.export_rules())

    def __get_ruleset(self, ruleset: str) -> List[str]:
        if ruleset.startswith(self._ruleset_prefix):
            action = ruleset[len(self._ruleset_prefix):]
        else:
            return []
        try:
            action_enum = Action(action.upper())
            final_action = action_enum
        except ValueError:
            final_action = action
        rules = self._ruleset_rules_manager.filter_rules_by_action(final_action)
        res = []
        for rule in rules:
            res.append(rule.rule.condition_string())
        return res

    def __insert_ruleset(self):
        outbounds = set()
        new_outbounds = set()
        self._top_rules_manager.remove_rules_by_lambda(
            lambda r: r.rule.rule_type == RuleType.RULE_SET and
                      r.remark == 'Auto' and
                      r.rule.payload != f"{self._ruleset_prefix}{ClashRuleParser.action_string(r.rule.action)}"
        )
        rules_existed = self._top_rules_manager.filter_rules_by_condition(
            lambda r: r.remark == 'Auto' and r.rule.rule_type == RuleType.RULE_SET
        )
        actions_existed = [ClashRuleParser.action_string(r.rule.action) for r in rules_existed]
        for r in self._ruleset_rules_manager.rules:
            rule = r.rule
            action_str = ClashRuleParser.action_string(rule.action)
            if action_str not in outbounds:
                outbounds.add(action_str)
            if action_str not in new_outbounds and action_str not in actions_existed:
                new_outbounds.add(action_str)
        self._top_rules_manager.remove_rules_by_lambda(
            lambda r: r.rule.rule_type == RuleType.RULE_SET and
                      r.remark == 'Auto' and
                      (ClashRuleParser.action_string(r.rule.action) not in outbounds or
                       r.rule.payload != f"{self._ruleset_prefix}{ClashRuleParser.action_string(r.rule.action)}")
        )
        for outbound in new_outbounds:
            clash_rule = ClashRuleParser.parse_rule_line(f"RULE-SET,{self._ruleset_prefix}{outbound},{outbound}")
            rule = RuleItem(rule=clash_rule, remark='Auto')
            if not self._top_rules_manager.has_rule_item(rule):
                self._top_rules_manager.insert_rule_at_priority(rule, 0)

    def append_top_rules(self, rules: List[str]) -> None:
        clash_rules = []
        for rule in rules:
            clash_rule = ClashRuleParser.parse_rule_line(rule)
            if not clash_rule:
                continue
            clash_rules.append(RuleItem(rule=clash_rule, remark='Manual'))
        self._top_rules_manager.append_rules(clash_rules)
        self.save_data('top_rules', self._top_rules_manager.export_rules())
        return

    @staticmethod
    def format_bytes(value_bytes):
        if value_bytes == 0:
            return '0 B'
        k = 1024
        sizes = ['B', 'KB', 'MB', 'GB', 'TB']
        i = math.floor(math.log(value_bytes) / math.log(k))
        return f"{value_bytes / math.pow(k, i):.2f} {sizes[i]}"

    @staticmethod
    def format_expire_time(timestamp):
        seconds_left = timestamp - int(time.time())
        days = seconds_left // 86400
        return f"{days}天后过期" if days > 0 else "已过期"

    def refresh_subscription_service(self):
        res = self.refresh_subscriptions()
        messages = []
        index = 1
        for url, result in res.items():
            try:
                host_name = UtilsProvider.get_url_domain(url)
            except ValueError:
                host_name = url
            message = f"{index}. 「 {host_name} 」\n"
            index += 1
            if result:
                sub_info = self._subscription_info.get(url, {})
                if sub_info.get('total') is not None:
                    used = sub_info.get('download', 0) + sub_info.get('upload', 0)
                    remaining = sub_info.get('total', 0) - used
                    info = (f"节点数量: {sub_info.get('proxy_num', 0)}\n"
                            f"已用流量: {ClashRuleProvider.format_bytes(used)}\n"
                            f"剩余流量: {ClashRuleProvider.format_bytes(remaining)}\n"
                            f"总量: {ClashRuleProvider.format_bytes(sub_info.get('total', 0))}\n"
                            f"过期时间: {ClashRuleProvider.format_expire_time(sub_info.get('expire', 0))}")
                else:
                    info = f"节点数量: {sub_info.get('proxy_num', 0)}\n"
                message += f"订阅更新成功\n{info}"
            else:
                message += '订阅更新失败'
            messages.append(message)
        if self._notify:
            self.post_message(title=f"【{self.plugin_name}】",
                              mtype=NotificationType.Plugin,
                              text='\n'.join(messages)
                              )

    def __refresh_acl4ssr(self):
        logger.info(f"Refreshing ACL4SSR ...")
        # 配置参数
        owner = 'ACL4SSR'
        repo = 'ACL4SSR'
        paths = ['Clash/Providers', 'Clash/Providers/Ruleset']
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/%s"
        branch = 'master'
        for path in paths:
            response = RequestUtils().get_res(api_url % path, headers=settings.GITHUB_HEADERS, params={'ref': branch})
            if not response:
                return
            files = response.json()
            yaml_files = [f for f in files if f["type"] == "file" and f["name"].endswith((".yaml", ".yml"))]
            self._acl4ssr_providers = {}
            for f in yaml_files:
                name = f"{self._acl4ssr_prefix}{f['name'][:f['name'].rfind('.')]}"
                path = f"./ACL4SSR/{f['name']}"
                provider = {'type': 'http', 'path': path, 'url': f["download_url"], 'interval': 600,
                            'behavior': 'classical', 'format': 'yaml', 'size-limit': 0}
                if name not in self._acl4ssr_providers:
                    self._acl4ssr_providers[name] = provider
        self.save_data('acl4ssr_providers', self._acl4ssr_providers)

    def __refresh_geo_dat(self):
        logger.info(f"Refreshing Geo Rules ...")
        owner = 'MetaCubeX'
        repo = 'meta-rules-dat'
        branch = 'meta'
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/geo"
        resp = RequestUtils().get_res(api_url, headers=settings.GITHUB_HEADERS, params={'ref': branch})
        if not resp:
            return
        for path in resp.json():
            if path["type"] == "dir" and path["name"] in self._geo_rules:
                tree_sha = path["sha"]
                url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{tree_sha}"
                res = RequestUtils().get_res(url, headers=settings.GITHUB_HEADERS, params={'ref': branch})
                if not res:
                    continue
                tree = res.json()
                yaml_files = [item["path"][:item["path"].rfind('.')] for item in tree["tree"] if
                              item["type"] == "blob" and item['path'].endswith((".yaml", ".yml"))]
                self._geo_rules[path["name"]] = yaml_files

    def refresh_subscriptions(self) -> Dict[str, bool]:
        """
        更新全部订阅链接
        """
        res = {}
        for index, sub_conf in enumerate(self._subscriptions_config):
            url = sub_conf['url']
            if not self._subscription_info.get(url, {}).get('enabled'):
                continue
            config, sub_info = self.__get_subscription(url, conf=sub_conf)
            if not config:
                res[url] = False
                continue
            self._subscription_info[url] = {**sub_info, 'enabled': True}
            res[url] = True
            self._clash_configs[url] = config
            remark = f"Sub:{UtilsProvider.get_url_domain(url)}-{abs(hash(url))}"
            self._proxies_manager.remove_proxies_by_condition(lambda p: p.remark == remark)
            self.__add_proxies_to_manager(config.get("proxies", []), remark)
        self.save_data('subscription_info', self._subscription_info)
        self.save_data('clash_configs', self._clash_configs)
        return res

    def __add_proxies_to_manager(self, proxies: List[Dict[str, Any]], remark: str, raw: Optional[str] = None):
        for proxy in proxies:
            try:
                self._proxies_manager.add_proxy_dict(proxy, remark=remark, raw=raw)
            except Exception as e:
                logger.error(f"Failed to add proxies: {e}")

    def __get_subscription(self, url: str, conf: Dict[str, Any]
                           ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        if not url:
            logger.error(f"Invalid links: {url}")
            return None, None
        logger.info(f"正在更新: {url}")
        ret = None
        for i in range(0, self._retry_times):
            ret = RequestUtils(accept_type="text/html", timeout=self._timeout,
                               proxies=settings.PROXY if self._proxy else None
                               ).get_res(url)
            if ret:
                break
        if not ret:
            logger.warn(f"更新失败: {url}.")
            return None, None
        try:
            rs: Dict[str, Any] = yaml.load(ret.content, Loader=yaml.SafeLoader)
            if type(rs) is str:
                all_proxies = {'name': "All Proxies", 'type': 'select', 'include-all-proxies': True}
                proxies = Converter.convert_v2ray(ret.content)
                if not proxies:
                    raise ValueError(f"Unknown content: {rs}")
                rs = {'proxies': proxies, 'proxy-groups': [all_proxies, ]}
            logger.info(f"已更新: {url}. 节点数量: {len(rs['proxies'])}")
            for key, default in ClashRuleProvider.DEFAULT_CLASH_CONF.items():
                rs.setdefault(key, default)
                if not conf.get(key, False):
                    rs[key] = default
            rs = self.__remove_nodes_by_keywords(rs)
        except Exception as e:
            logger.error(f"解析配置出错： {e}")
            return None, None

        sub_info = {'last_update': int(time.time()), 'proxy_num': len(rs.get('proxies', []))}
        if 'Subscription-Userinfo' in ret.headers:
            matches = re.findall(r'(\w+)=(\d+)', ret.headers['Subscription-Userinfo'])
            variables = {key: int(value) for key, value in matches}
            sub_info.update({
                'download': variables['download'],
                'upload': variables['upload'],
                'total': variables['total'],
                'expire': variables['expire']
            })
        return rs, sub_info

    def notify_clash(self, ruleset: str):
        """
        通知 Clash 刷新规则集
        """
        for clash_dashboard in self._clash_dashboards:
            clash_dashboard_url = clash_dashboard.get('url', '')
            clash_dashboard_secret = clash_dashboard.get('secret', '')
            url = f'{clash_dashboard_url}/providers/rules/{ruleset}'
            RequestUtils(content_type="application/json", timeout=self._timeout,
                         headers={"authorization": f"Bearer {clash_dashboard_secret}"}
                         ).put(url)

    def proxy_groups_by_region(self) -> List[Dict[str, Any]]:
        countries = self.countries()
        return self.__group_by_region(countries, self.proxies())

    @cached(maxsize=1, ttl=86400, skip_empty=True)
    def countries(self) -> List[Dict[str, str]]:
        file_path = settings.ROOT_PATH / 'app' / 'plugins' / self.__class__.__name__.lower() / 'countries.json'
        try:
            countries = json.load(open(file_path))
        except Exception as e:
            logger.error(f"插件加载错误：{e}")
            return []
        return countries

    @cached(maxsize=1, ttl=86400)
    def __group_by_region(self, countries: List[Dict[str, str]], proxies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        continent_groups = {}
        country_groups = {}
        continent_map = {
            '欧洲': 'Europe',
            '亚洲': 'Asia',
            '大洋洲': 'Oceania',
            '非洲': 'Africa',
            '北美洲': 'NorthAmerica',
            '南美洲': 'SouthAmerica'
        }
        proxy_groups: List[Dict[str, Any]] = []
        hk = next(filter(lambda c: c['abbr'] == 'HK', countries),
                  {"abbr": "HK", "chinese": "中国香港特别行政区", "emoji": "🇭🇰"})
        tw = next(filter(lambda c: c['abbr'] == 'TW', countries),
                  {"abbr": "TW", "chinese": "中国台湾", "emoji": "🇹🇼"})
        for proxy_node in proxies:
            country = ClashRuleProvider.__country_from_node(countries, proxy_node['name'])
            if not country:
                continue
            if country.get("abbr") == "CN":
                if any(key in proxy_node["name"] for key in ("🇭🇰", "HK", "香港")):
                    country = hk
                if any(key in proxy_node["name"] for key in ("🇹🇼", "TW", "台湾")):
                    country = tw
            continent = continent_map[country.get('continent')]
            if self._group_by_region:
                continent_groups.setdefault(continent, []).append(proxy_node['name'])
            if self._group_by_country:
                country_groups.setdefault(f"{country.get('emoji')} {country.get('chinese')}", []).append(
                    proxy_node['name'])
        for continent, nodes in continent_groups.items():
            if len(nodes):
                proxy_group = {'name': continent, 'type': 'select', 'proxies': nodes}
                proxy_groups.append(proxy_group)
        excluded = ('中国', '香港', 'CN', 'HK', '🇨🇳', '🇭🇰')
        for continent_node in continent_groups.get('Asia', []):
            if any(x in continent_node for x in excluded):
                continue
            continent_groups.setdefault('AsiaExceptChina', []).append(continent_node)
        if continent_groups.get('AsiaExceptChina'):
            proxy_group = {'name': 'AsiaExceptChina', 'type': 'select', 'proxies': continent_groups['AsiaExceptChina']}
            proxy_groups.append(proxy_group)
        for country, nodes in country_groups.items():
            if len(nodes):
                proxy_group = {'name': country, 'type': 'select', 'proxies': nodes}
                proxy_groups.append(proxy_group)
        country_group = list(country_groups.keys())
        if country_group:
            proxy_groups.append({'name': '🏴‍☠️国家分组', 'type': 'select', 'proxies': country_group})

        for proxy_group in proxy_groups:
            if proxy_group['name'] in self._overwritten_region_groups:
                proxy_group.update(self._overwritten_region_groups[proxy_group['name']])

        return proxy_groups

    @staticmethod
    def __country_from_node(countries: List[Dict[str, str]], node_name: str) -> Optional[Dict[str, str]]:
        node_name_lower = node_name.lower()
        for country in countries:
            if country['emoji'] and country['emoji'] in node_name:
                return country
            elif (
                    country['chinese'] in node_name
                    or country['english'].lower() in node_name_lower
            ):
                return country

        return None

    def __add_notification_job(self, ruleset_names: List[str]):
        if not self._enabled or not self._scheduler:
            return
        for ruleset in ruleset_names:
            if ruleset in self._rule_provider:
                self._scheduler.add_job(self.notify_clash, "date",
                                        run_date=datetime.now(
                                            tz=pytz.timezone(settings.TZ)) + timedelta(seconds=self._refresh_delay),
                                        args=[ruleset],
                                        id=f'CRP-notify-clash{ruleset}',
                                        replace_existing=True
                                        )

    def __remove_nodes_by_keywords(self, clash_config: Dict[str, Any]) -> Dict[str, Any]:
        removed_proxies = []
        proxies = []
        for proxy in clash_config.get("proxies", []):
            has_keywords = bool(len([x for x in self._filter_keywords if x in proxy.get("name", '')]))
            if has_keywords:
                removed_proxies.append(proxy.get("name"))
            else:
                proxies.append(proxy)
        if proxies:
            clash_config["proxies"] = proxies
        else:
            logger.warn(f"关键词过滤后无可用节点，跳过过滤")
            removed_proxies = []
        for proxy_group in clash_config.get("proxy-groups", []):
            proxy_group['proxies'] = [x for x in proxy_group.get('proxies', []) if x not in removed_proxies]
        return clash_config

    def proxies(self, regex: Optional[str] = None, flat: bool = True) -> List[Dict[str, Any]]:
        """
        获取出站代理
        """
        def __overwrite_proxy(_proxy: Dict[str, Any], _overwritten_proxies: Dict[str, Any]) -> Dict[str, Any]:
            if _proxy['name'] in _overwritten_proxies:
                for key in ['base', 'tls', 'network']:
                    _proxy.update(copy.deepcopy(_overwritten_proxies[_proxy['name']].get(key)) or {})
            return _proxy
        if regex is None:
            proxies = list(self._proxies_manager)
        else:
            proxies = self._proxies_manager.filter_proxies_by_condition(
                           lambda proxy_item: bool(re.compile(regex).match(proxy_item.remark))
                       )
        ret = []
        for p in proxies:
            proxy = __overwrite_proxy(p.proxy.dict(by_alias=True, exclude_none=True), self._overwritten_proxies)
            if flat:
                ret.append(proxy)
            else:
                ret.append({'proxy':proxy, 'raw': p.raw, 'remark': p.remark})
        return ret

    def all_proxy_providers(self) -> Dict[str, Any]:
        """
        所有代理集合
        """
        proxy_providers = self.value_from_sub_conf('proxy-providers')
        proxy_providers.update(self._clash_template_dict.get('proxy-providers', {}))
        return proxy_providers

    def value_from_sub_conf(
            self,
            key: Literal['rules', 'rule-providers', 'proxies', 'proxy-groups', 'proxy-providers']
    ) -> Union[Dict[str, Any], List[Any]]:
        default = copy.deepcopy(self.DEFAULT_CLASH_CONF[key])
        for conf in self._subscriptions_config:
            url = conf["url"]
            config = self._clash_configs.get(url, {})
            if isinstance(default, dict):
                default.update(config.get(key, {}))
            elif isinstance(default, list):
                default.extend(config.get(key, []))
        return default

    def dict_from_sub_conf(
            self,
            key: Literal['rules', 'rule-providers', 'proxies', 'proxy-groups', 'proxy-providers']
    ) -> Dict[str, Any]:
        result = {}
        for conf in self._subscriptions_config:
            url = conf["url"]
            config = self._clash_configs.get(url, {})
            result[key] = config.get(key, copy.deepcopy(self.DEFAULT_CLASH_CONF[key]))
        return result

    @staticmethod
    def extend_with_name_checking(to_list: List[Dict[str, Any]], from_list: List[Dict[str, Any]]
                                  ) -> List[Dict[str, Any]]:
        """
        去除同名元素合并列表
        """
        for item in from_list:
            if any(p.get('name') == item.get('name', '') for p in to_list):
                logger.warn(f"Item named {item.get('name')!r} already exists. Skipping...")
                continue
            to_list.append(item)
        return to_list

    @staticmethod
    def update_with_checking(src_dict: Dict[str, Any], dst_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        跳过存在的键合并字典
        """
        for key, value in src_dict.items():
            if key in dst_dict:
                logger.warn(f"{key!r} already exists. Skipping...")
                continue
            dst_dict[key] = value
        return dst_dict

    @staticmethod
    def remove_invalid_outbounds(proxies: List[Dict[str, Any]], proxy_groups: List[Dict[str, Any]]
                                 ) -> List[Dict[str, Any]]:
        """
        从代理组中移除无效的出站
        """
        outbounds = {proxy.get('name') for proxy in proxies if proxy.get('name')} | \
                    {proxy_group.get('name') for proxy_group in proxy_groups if proxy_group.get('name')} | \
                    {action.value for action in Action}
        outbounds.add('GLOBAL')
        for proxy_group in proxy_groups:
            ps = []
            if proxy_group.get('proxies'):
                for proxy in proxy_group.get('proxies', []):
                    if proxy in outbounds:
                        ps.append(proxy)
                    else:
                        logger.warn(f"Proxy {proxy!r} in {proxy_group.get('name')!r} doesn't exist. Skipping...")
                proxy_group['proxies'] = ps
        return proxy_groups

    @staticmethod
    def remove_invalid_proxy_providers(providers: Dict[str, Any], proxy_groups: List[Dict[str, Any]]
                                       ) -> List[Dict[str, Any]]:
        provider_names = providers.keys()
        for proxy_group in proxy_groups:
            ps = []
            if proxy_group.get('use'):
                for provider in proxy_group.get('use', []):
                    if provider in provider_names:
                        ps.append(provider)
                    else:
                        logger.warn(f"Proxy provider {provider!r} in {proxy_group.get('name')!r} doesn't exist. "
                                    f"Skipping...")
                proxy_group['use'] = ps
        return proxy_groups

    @staticmethod
    def build_graph(config: Dict[str, Any]) -> Dict[str, Any]:
        """构建代理组有向图"""
        graph = {}
        groups = config.get("proxy-groups", [])
        group_names = {g["name"] for g in groups}
        for group in groups:
            name = group["name"]
            proxies = group.get("proxies", [])
            graph[name] = [p for p in proxies if p in group_names]
        return graph

    def clash_config(self) -> Optional[Dict[str, Any]]:
        """
        综合 clash 配置，返回配置字典
        """
        proxies = []
        if not self._clash_template_dict:
            clash_config = copy.deepcopy({**ClashRuleProvider.DEFAULT_CLASH_CONF})
        else:
            clash_config = copy.deepcopy(self._clash_template_dict)

        for key, default in ClashRuleProvider.DEFAULT_CLASH_CONF.items():
            if isinstance(default, dict):
                ClashRuleProvider.update_with_checking(self.value_from_sub_conf(key), clash_config.get(key, {}))
            elif isinstance(default, list):
                ClashRuleProvider.extend_with_name_checking(clash_config.get(key, []), self.value_from_sub_conf(key))

        for proxy in self.proxies():
            if any(p.get('name') == proxy.get('name', '') for p in proxies):
                logger.warn(f"Proxy named {proxy.get('name')!r} already exists. Skipping...")
                continue
            proxies.append(proxy)
        if proxies:
            clash_config['proxies'] = proxies
        self.__insert_ruleset()
        # 添加代理组
        proxy_groups = copy.deepcopy(self._proxy_groups)
        if proxy_groups:
            clash_config['proxy-groups'] = ClashRuleProvider.extend_with_name_checking(clash_config['proxy-groups'],
                                                                                       proxy_groups)
        # 添加按大洲代理组
        if self._group_by_region or self._group_by_country:
            groups_by_region = self.proxy_groups_by_region()
            if groups_by_region:
                clash_config['proxy-groups'] = ClashRuleProvider.extend_with_name_checking(clash_config['proxy-groups'],
                                                                                           groups_by_region)
        # 移除无效出站, 避免配置错误
        clash_config['proxy-groups'] = ClashRuleProvider.remove_invalid_outbounds(clash_config.get('proxies', []),
                                                                                  clash_config.get('proxy-groups', []))
        clash_config['proxy-groups'] = ClashRuleProvider.remove_invalid_proxy_providers(
            self.all_proxy_providers(),
            clash_config.get('proxy-groups', [])
        )
        top_rules = []
        outbound_names = list(x.get("name") for x in self.clash_outbound())

        # 添加 extra rule providers
        if self._extra_rule_providers:
            clash_config['rule-providers'].update(self._extra_rule_providers)

        # 通过 ruleset rules 添加 rule-providers
        self._rule_provider = {}
        for r in self._ruleset_rules_manager.rules:
            rule = r.rule
            action_str = ClashRuleParser.action_string(rule.action)
            rule_provider_name = f'{self._ruleset_prefix}{action_str}'
            if rule_provider_name not in self._rule_provider:
                path_name = hashlib.sha256(action_str.encode('utf-8')).hexdigest()[:10]
                self._ruleset_names[path_name] = rule_provider_name
                sub_url = (f"{self._movie_pilot_url}/api/v1/plugin/ClashRuleProvider/ruleset?"
                           f"name={path_name}&apikey={self._apikey or settings.API_TOKEN}")
                self._rule_provider[rule_provider_name] = {"behavior": "classical",
                                                           "format": "yaml",
                                                           "interval": 3600,
                                                           "path": f"./CRP/{path_name}.yaml",
                                                           "type": "http",
                                                           "url": sub_url}
        clash_config['rule-providers'].update(self._rule_provider)
        # 添加规则
        for r in self._top_rules_manager:
            rule = r.rule
            if not isinstance(rule.action, Action) and rule.action not in outbound_names:
                logger.warn(f"出站 {rule.action} 不存在, 跳过 {rule.raw_rule}")
                continue
            if rule.rule_type == RuleType.RULE_SET:
                # 添加ACL4SSR Rules
                if rule.payload in self._acl4ssr_providers:
                    clash_config['rule-providers'][rule.payload] = self._acl4ssr_providers[rule.payload]
                if rule.payload not in clash_config.get('rule-providers', {}):
                    logger.warn(f"规则集合 {rule.payload!r} 不存在, 跳过 {rule.raw_rule!r}")
                    continue
            top_rules.append(rule.raw_rule)
        for raw_rule in clash_config.get("rules", []):
            rule = ClashRuleParser.parse_rule_line(raw_rule)
            if not rule:
                logger.warn(f"无效的规则 {raw_rule!r}, 跳过")
                continue
            if not isinstance(rule.action, Action) and rule.action not in outbound_names:
                logger.warn(f"出站 {rule.action!r} 不存在, 跳过 {rule.raw_rule!r}")
                continue
            top_rules.append(rule.raw_rule)
        clash_config["rules"] = top_rules

        # 添加 Hosts
        if self._hosts:
            clash_config.setdefault('hosts', {})
            new_hosts = {
                item['domain']: item.get('value', []) if not item.get('using_cloudflare') else self._best_cf_ip
                for item in self._hosts if item.get('domain')
            }
            clash_config["hosts"] = {**clash_config["hosts"], **new_hosts}

        if self._rule_provider:
            clash_config['rule-providers'] = clash_config.get('rule-providers') or {}
            clash_config['rule-providers'].update(self._rule_provider)

        key_to_delete = []
        for key, item in self._ruleset_names.items():
            if item not in clash_config.get('rule-providers', {}):
                key_to_delete.append(key)
        for key in key_to_delete:
            del self._ruleset_names[key]
        if not clash_config.get("rule-providers"):
            del clash_config["rule-providers"]

        # 对代理组进行回环检测
        proxy_graph = ClashRuleProvider.build_graph(clash_config)
        cycles = UtilsProvider.find_cycles(proxy_graph)
        # 警告但不处理
        if cycles:
            logger.warn("发现代理组回环：")
            for cycle in cycles:
                logger.warn(" -> ".join(cycle))

        self.save_data('ruleset_names', self._ruleset_names)
        self.save_data('rule_provider', self._rule_provider)
        return clash_config

    @property
    def best_cf_ipv4(self) -> List[str]:
        v4 = [ip for ip in self._best_cf_ip if IpUtils.is_ipv4(ip)]
        return v4

    @property
    def best_cf_ipv6(self) -> List[str]:
        v6 = [ip for ip in self._best_cf_ip if IpUtils.is_ipv6(ip)]
        return v6

    @eventmanager.register(EventType.PluginAction)
    def update_cloudflare_ips_handler(self, event: Event = None):
        event_data = event.event_data
        if not event_data or event_data.get("action") != "update_cloudflare_ips":
            return
        ips = event_data.get("ips")
        if isinstance(ips, str):
            ips = [ips]
        if isinstance(ips, list):
            logger.info(f"更新 Cloudflare 优选 IP ...")
            self.update_best_cf_ip(ips)
