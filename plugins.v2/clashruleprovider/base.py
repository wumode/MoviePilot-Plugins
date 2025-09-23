from abc import abstractmethod
from typing import Final, Optional, Literal, Dict

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.plugins import _PluginBase

from .state import PluginState
from .config import PluginConfig


class _ClashRuleProviderBase(_PluginBase):
    # Constants
    DEFAULT_CLASH_CONF: Final[
        Dict[Literal['rules', 'rule-providers', 'proxies', 'proxy-groups', 'proxy-providers'], dict | list]] = {
        'rules': [], 'rule-providers': {},
        'proxies': [], 'proxy-groups': [], 'proxy-providers': {}
    }
    OVERWRITTEN_PROXIES_LIFETIME: Final[int] = 10
    ACL4SSR_API_URL: Final[str] = "https://api.github.com/repos/ACL4SSR/ACL4SSR/contents/"
    MISFIRE_GRACE_TIME: Final[int] = 120

    def __init__(self):
        # Configuration attributes
        super().__init__()

        # Runtime variables
        self.state: Optional[PluginState] = None
        self.config: Optional[PluginConfig] = None
        self.scheduler: Optional[AsyncIOScheduler] = None

    @abstractmethod
    def load_proxies(self):
        pass

    @abstractmethod
    def save_proxies(self):
        pass

    @abstractmethod
    def load_rules(self):
        pass

    @abstractmethod
    def save_rules(self):
        pass
