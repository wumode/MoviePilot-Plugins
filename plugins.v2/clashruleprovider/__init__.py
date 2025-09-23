import copy
import pytz
import time
import yaml
from datetime import datetime, timedelta
from typing import Any, Optional, List, Dict, Tuple

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from app.core.config import settings
from app.core.event import eventmanager, Event
from app.log import logger
from app.scheduler import Scheduler
from app.schemas.types import EventType

from .api import ClashRuleProviderApi, apis
from .base import _ClashRuleProviderBase
from .config import PluginConfig
from .helper.configconverter import Converter
from .helper.clashruleparser import ClashRuleParser, Action, RuleType, ClashRule
from .helper.utilsprovider import UtilsProvider
from .state import PluginState
from .services import ClashRuleProviderService


class ClashRuleProvider(_ClashRuleProviderBase):
    # 插件名称
    plugin_name = "Clash Rule Provider"
    # 插件描述
    plugin_desc = "随时为Clash添加一些额外的规则。"
    # 插件图标
    plugin_icon = "Mihomo_Meta_A.png"
    # 插件版本
    plugin_version = "2.0.4"
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

    def __init__(self):
        # Configuration attributes
        super().__init__()

        # Runtime variables
        self.services: ClashRuleProviderService = ClashRuleProviderService(self)
        self.api: ClashRuleProviderApi = ClashRuleProviderApi(self, self.services)

    def init_plugin(self, conf: dict = None):
        self.stop_service()
        self.state = PluginState()
        self.config = PluginConfig()
        # Load persistent data into state
        self.state.proxy_groups = self.get_data("proxy_groups") or []
        self.state.extra_proxies = self.get_data("extra_proxies") or []
        self.state.subscription_info = self.get_data("subscription_info") or {}
        self.state.rule_provider = self.get_data("rule_provider") or {}
        self.state.rule_providers = self.get_data("extra_rule_providers") or {}
        self.state.ruleset_names = self.get_data("ruleset_names") or {}
        self.state.acl4ssr_providers = self.get_data("acl4ssr_providers") or {}
        self.state.clash_configs = self.get_data("clash_configs") or {}
        self.state.hosts = self.get_data("hosts") or []
        self.state.overwritten_region_groups = self.get_data("overwritten_region_groups") or {}
        self.state.overwritten_proxies = self.get_data("overwritten_proxies") or {}
        self.state.geo_rules = self.get_data("geo_rules") or {'geoip': [], 'geosite': []}

        if conf:
            self.config.from_dict(conf)
        self.__update_config()

        if self.config.enabled:
            self._initialize_plugin()

    def _initialize_plugin(self):
        self.state.proxies_manager.clear()
        self.state.top_rules_manager.clear()
        self.state.ruleset_rules_manager.clear()

        try:
            self.state.clash_template_dict = yaml.load(self.config.clash_template, Loader=yaml.SafeLoader) or {}
            if not isinstance(self.state.clash_template_dict, dict):
                self.state.clash_template_dict = {}
                logger.error("Invalid clash template yaml")
        except yaml.YAMLError as exc:
            logger.error(f"Error loading clash template yaml: {exc}")
            self.state.clash_template_dict = {}

        # Normalize template
        for key, default in self.DEFAULT_CLASH_CONF.items():
            self.state.clash_template_dict.setdefault(key, copy.deepcopy(default))

        self.load_rules()
        self.load_proxies()

        self.state.subscription_info = {url: self.state.subscription_info.get(url) or {}
                                        for url in self.config.sub_links}
        for _, sub_info in self.state.subscription_info.items():
            sub_info.setdefault('enabled', True)
        self.state.clash_configs = {url: self.state.clash_configs[url] for url in self.config.sub_links if
                                    self.state.clash_configs.get(url)}

        for url, conf in self.state.clash_configs.items():
            self.services.add_proxies_to_manager(conf.get('proxies', []),
                                                 f"Sub:{UtilsProvider.get_url_domain(url)}-{abs(hash(url))}")
        self.services.add_proxies_to_manager(self.state.clash_template_dict.get('proxies', []), 'Template')

        self.services.check_proxies_lifetime()
        self._start_scheduler()

    def _start_scheduler(self):
        self.scheduler = AsyncIOScheduler(timezone=settings.TZ, event_loop=Scheduler().loop)
        self.scheduler.start()
        now = datetime.now(tz=pytz.timezone(settings.TZ))
        self.scheduler.add_job(self.services.async_refresh_subscriptions, "date",
                               run_date=now + timedelta(seconds=2), misfire_grace_time=self.MISFIRE_GRACE_TIME)
        if self.config.hint_geo_dat:
            self.scheduler.add_job(self.services.async_refresh_geo_dat, "date",
                                   run_date=now + timedelta(seconds=3), misfire_grace_time=self.MISFIRE_GRACE_TIME)
        else:
            self.state.geo_rules = {'geoip': [], 'geosite': []}
        if self.config.enable_acl4ssr:
            self.scheduler.add_job(self.services.async_refresh_acl4ssr, "date",
                                   run_date=now + timedelta(seconds=4), misfire_grace_time=self.MISFIRE_GRACE_TIME)
        else:
            self.state.acl4ssr_providers = {}

    def get_state(self) -> bool:
        return self.config.enabled

    @staticmethod
    def get_command() -> List[Dict[str, Any]]:
        pass

    def get_api(self) -> List[Dict[str, Any]]:
        return apis.get_routes(self.api)

    def get_render_mode(self) -> Tuple[str, str]:
        return "vue", "dist/assets"

    def get_form(self) -> Tuple[List[dict], Dict[str, Any]]:
        return [], {}

    def get_dashboard_meta(self) -> Optional[List[Dict[str, str]]]:
        components = [
            {"key": "clash_info", "name": "Clash Info"},
            {"key": "traffic_stats", "name": "Traffic Stats"}
        ]
        return [c for c in components if c.get("name") in self.config.dashboard_components]

    def get_dashboard(self, key: str, **kwargs) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], List[dict]]]:
        clash_available = bool(self.config.dashboard_url and self.config.dashboard_secret)
        components = {'clash_info': {'title': 'Clash Info', 'md': 4},
                      'traffic_stats': {'title': 'Traffic Stats', 'md': 8}}
        col_config = {'cols': 12, 'md': components.get(key, {}).get('md', 4)}
        global_config = {
            'title': components.get(key, {}).get('title', 'Clash Info'),
            'border': True,
            'clash_available': clash_available,
            'secret': self.config.dashboard_secret,
        }
        return col_config, global_config, []

    def get_page(self) -> List[dict]:
        return []

    def stop_service(self):
        if self.scheduler:
            try:
                self.scheduler.remove_all_jobs()
                if self.scheduler.running:
                    self.scheduler.shutdown()
                self.scheduler = None
            except Exception as e:
                logger.error(f"退出插件失败：{e}")

    def get_service(self) -> List[Dict[str, Any]]:
        if self.get_state() and self.config.auto_update_subscriptions and self.config.sub_links:
            return [{
                "id": "ClashRuleProvider",
                "name": "定时更新订阅",
                "trigger": CronTrigger.from_crontab(self.config.cron_string),
                "func": self.services.refresh_subscription_service,
                "kwargs": {}
            }]
        return []

    def __update_config(self):
        conf = self.config.to_dict()
        self.update_config(conf)

    def update_best_cf_ip(self, ips: List[str]):
        self.config.best_cf_ip = [*ips]
        conf = self.get_config()
        conf['best_cf_ip'] = self.config.best_cf_ip
        self.update_config(conf)

    def load_proxies(self):
        proxies = self.get_data("proxies") or []
        initial_len = len(proxies)
        proxies.extend(self.state.extra_proxies)
        invalid_proxies = []
        converter = Converter()
        for proxy in proxies:
            try:
                if isinstance(proxy, dict):
                    proxy = UtilsProvider.filter_empty(proxy, empty=['', None])
                    self.state.proxies_manager.add_proxy_dict(proxy, remark='Manual')
                elif isinstance(proxy, str):
                    proxy_dict = converter.convert_line(proxy)
                    if proxy_dict:
                        self.state.proxies_manager.add_proxy_dict(proxy_dict, remark='Manual', raw=proxy)
            except Exception as e:
                logger.error(f"Failed to load proxy {proxy}: {e}")
                invalid_proxies.append(proxy)
        if len(self.state.extra_proxies) != len(invalid_proxies):
            self.state.extra_proxies = invalid_proxies
            self.save_data('extra_proxies', self.state.extra_proxies)
        if len(self.state.proxies_manager) > initial_len:
            self.save_proxies()

    def save_proxies(self):
        proxies = self.state.proxies_manager.export_raw(condition=lambda proxy: proxy.remark == 'Manual')
        self.save_data('proxies', proxies)

    def load_rules(self):
        def process_rules(raw_rules, manager, key):
            raw_rules = raw_rules or []
            rules = [self.__upgrade_rule(r) if isinstance(r, str) else r for r in raw_rules]
            manager.import_rules(rules)
            if any((isinstance(r, str) or 'time_modified' not in r) for r in raw_rules):
                self.save_data(key, manager.export_rules())

        process_rules(self.get_data("top_rules"), self.state.top_rules_manager, "top_rules")
        process_rules(self.get_data("ruleset_rules"), self.state.ruleset_rules_manager, "ruleset_rules")

    def save_rules(self):
        self.save_data('top_rules', self.state.top_rules_manager.export_rules())
        self.save_data('ruleset_rules', self.state.ruleset_rules_manager.export_rules())

    def __upgrade_rule(self, rule_string: str) -> Dict[str, str]:
        rule = ClashRuleParser.parse_rule_line(rule_string)
        remark = 'Manual'
        if isinstance(rule, ClashRule) and rule.rule_type == RuleType.RULE_SET and rule.payload.startswith(
                self.config.ruleset_prefix):
            remark = 'Auto'
        return {'rule': rule_string, 'remark': remark, 'time_modified': time.time()}

    @eventmanager.register(EventType.PluginAction)
    def update_cloudflare_ips_handler(self, event: Event = None):
        event_data = event.event_data
        if not event_data or event_data.get("action") != "update_cloudflare_ips":
            return
        ips = event_data.get("ips")
        if isinstance(ips, str):
            ips = [ips]
        if isinstance(ips, list):
            logger.info("更新 Cloudflare 优选 IP ...")
            self.update_best_cf_ip(ips)
