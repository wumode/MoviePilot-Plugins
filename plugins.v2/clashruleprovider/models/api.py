from typing import List, Optional, Union, Literal

from pydantic import BaseModel, Field

from .ruleproviders import RuleProvider
from ..helper.clashruleparser import RuleType, Action, AdditionalParam

class RuleData(BaseModel):
    priority: int
    type: RuleType
    payload: str
    action: Union[Action, str]
    additional_params: Optional[AdditionalParam] = None

    class Config:
        use_enum_values = True

class ClashApi(BaseModel):
    url: str
    secret: str

class Connectivity(BaseModel):
    clash_apis: List[ClashApi] = Field(default_factory=list)
    sub_links: List[str] = Field(default_factory=list)

class Subscription(BaseModel):
    url: str

class RuleProviderData(BaseModel):
    name: str
    rule_provider: RuleProvider

class SubscriptionInfo(BaseModel):
    url: str
    field: Literal['name', 'enabled']
    value: str

class HostData(BaseModel):
    domain: str
    value: List[str]
    using_cloudflare: bool

class HostRequest(BaseModel):
    domain: str
    value: Optional[HostData] = None