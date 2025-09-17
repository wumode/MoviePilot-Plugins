import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional, Union


class AdditionalParam(Enum):
    NO_RESOLVE = 'no-resolve'
    SRC = 'src'


class RuleType(Enum):
    """Enumeration of all supported Clash rule types"""
    DOMAIN = "DOMAIN"
    DOMAIN_SUFFIX = "DOMAIN-SUFFIX"
    DOMAIN_KEYWORD = "DOMAIN-KEYWORD"
    DOMAIN_REGEX = "DOMAIN-REGEX"
    DOMAIN_WILDCARD = "DOMAIN-WILDCARD"

    GEOSITE = "GEOSITE"
    GEOIP = "GEOIP"

    IP_CIDR = "IP-CIDR"
    IP_CIDR6 = "IP-CIDR6"
    IP_SUFFIX = "IP-SUFFIX"
    IP_ASN = "IP-ASN"


    SRC_GEOIP = "SRC-GEOIP"
    SRC_IP_ASN = "SRC-IP-ASN"
    SRC_IP_CIDR = "SRC-IP-CIDR"
    SRC_IP_SUFFIX = "SRC-IP-SUFFIX"

    DST_PORT = "DST-PORT"
    SRC_PORT = "SRC-PORT"

    IN_PORT = "IN-PORT"
    IN_TYPE = "IN-TYPE"
    IN_USER = "IN-USER"
    IN_NAME = "IN-NAME"

    PROCESS_PATH = "PROCESS-PATH"
    PROCESS_PATH_REGEX = "PROCESS-PATH-REGEX"
    PROCESS_NAME = "PROCESS-NAME"
    PROCESS_NAME_REGEX = "PROCESS-NAME-REGEX"

    UID = "UID"
    NETWORK = "NETWORK"
    DSCP = "DSCP"

    RULE_SET = "RULE-SET"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    SUB_RULE = "SUB-RULE"

    MATCH = "MATCH"


class Action(Enum):
    """Enumeration of rule actions"""
    DIRECT = "DIRECT"
    REJECT = "REJECT"
    REJECT_DROP = "REJECT-DROP"
    PASS = "PASS"
    COMPATIBLE = "COMPATIBLE"


@dataclass
class ClashRule:
    """Represents a parsed Clash routing rule"""
    rule_type: RuleType
    payload: str
    action: Union[Action, str]  # Can be Action enum or custom proxy group name
    additional_params: Optional[AdditionalParam] = None
    raw_rule: str = field(default="")

    def condition_string(self) -> str:
        return f"{self.rule_type.value},{self.payload}"

    def to_dict(self) -> Dict[str, str]:
        return {
            'type': self.rule_type.value,
            'payload': self.payload,
            'action': self.action.value if isinstance(self.action, Action) else self.action,
            'additional_params': self.additional_params,
            'raw': self.raw_rule
        }


@dataclass
class LogicRule:
    """Represents a logic rule (AND, OR, NOT)"""
    logic_type: RuleType
    conditions: List[Union[ClashRule, 'LogicRule']]
    action: Union[Action, str]
    raw_rule: str = field(default="")

    def condition_string(self) -> str:
        conditions_str = ','.join([f"({c.condition_string()})" for c in self.conditions])
        return f"{self.logic_type.value},({conditions_str})"

    def to_dict(self) -> Dict[str, str]:
        conditions_dict = []
        for condition in self.conditions:
            if isinstance(condition, ClashRule):
                conditions_dict.append({
                    'type': condition.rule_type.value,
                    'payload': condition.payload
                })

        return {
            'type': self.logic_type.value,
            'conditions': conditions_dict,
            'action': self.action.value if isinstance(self.action, Action) else self.action,
            'raw': self.raw_rule
        }


@dataclass
class MatchRule:
    """Represents a match rule"""
    action: Union[Action, str]
    raw_rule: str = field(default="")
    rule_type: RuleType = RuleType.MATCH

    @staticmethod
    def condition_string() -> str:
        return "MATCH"

    def to_dict(self) -> Dict[str, str]:
        return {
            'type': 'MATCH',
            'action': self.action.value if isinstance(self.action, Action) else self.action,
            'raw': self.raw_rule
        }


class ClashRuleParser:
    """Parser for Clash routing rules"""

    @staticmethod
    def parse_rule_line(line: str) -> Optional[Union[ClashRule, LogicRule, MatchRule]]:
        """Parse a single rule line"""
        line = line.strip()
        try:
            # Handle logic rules (AND, OR, NOT)

            if line.startswith(('AND,', 'OR,', 'NOT,')):
                return ClashRuleParser._parse_logic_rule(line)
            elif line.startswith('MATCH'):
                return ClashRuleParser._parse_match_rule(line)
            # Handle regular rules
            return ClashRuleParser._parse_regular_rule(line)

        except Exception as e:
            return None

    @staticmethod
    def parse_rule_dict(clash_rule: Dict[str, Any]) -> Optional[Union[ClashRule, LogicRule, MatchRule]]:
        if not clash_rule:
            return None
        if clash_rule.get("type") in ('AND', 'OR', 'NOT'):
            conditions = clash_rule.get("conditions")
            if not conditions:
                return None
            conditions_str = ''
            for condition in conditions:
                conditions_str += f'({condition.get("type")},{condition.get("payload")})'
            conditions_str = f"({conditions_str})"
            raw_rule = f"{clash_rule.get('type')},{conditions_str},{clash_rule.get('action')}"
            rule = ClashRuleParser._parse_logic_rule(raw_rule)
        elif clash_rule.get("type") == 'MATCH':
            raw_rule = f"{clash_rule.get('type')},{clash_rule.get('action')}"
            rule = ClashRuleParser._parse_match_rule(raw_rule)
        else:
            raw_rule = f"{clash_rule.get('type')},{clash_rule.get('payload')},{clash_rule.get('action')}"
            if clash_rule.get('additional_params'):
                raw_rule += f',{clash_rule.get('additional_params')}'
            rule = ClashRuleParser._parse_regular_rule(raw_rule)
        if rule and 'priority' in clash_rule:
            rule.priority = clash_rule['priority']
        return rule

    @staticmethod
    def _parse_match_rule(line: str) -> MatchRule:
        parts = line.split(',')
        if len(parts) < 2:
            raise ValueError(f"Invalid rule format: {line}")
        action = parts[1].strip()
        # Validate rule type
        try:
            action_enum = Action(action.upper())
            final_action = action_enum
        except ValueError:
            final_action = action

        return MatchRule(
            action=final_action,
            raw_rule=line
        )

    @staticmethod
    def _parse_regular_rule(line: str) -> ClashRule:
        """Parse a regular (non-logic) rule"""
        parts = line.split(',')

        if len(parts) < 3 or len(parts) > 4:
            raise ValueError(f"Invalid rule format: {line}")

        rule_type_str = parts[0].upper().strip()
        payload = parts[1].strip()
        action = parts[2].strip()

        if not payload or not rule_type_str:
            raise ValueError(f"Invalid rule format: {line}")

        additional_params = parts[3].strip() if len(parts) > 3 else None

        # Validate rule type
        try:
            rule_type = RuleType(rule_type_str)
        except ValueError:
            raise ValueError(f"Unknown rule type: {rule_type_str}")

        # Try to convert action to enum, otherwise keep as string (custom proxy group)
        try:
            action_enum = Action(action.upper())
            final_action = action_enum
        except ValueError:
            final_action = action

        return ClashRule(
            rule_type=rule_type,
            payload=payload,
            action=final_action,
            additional_params=additional_params,
            raw_rule=line
        )

    @staticmethod
    def _parse_logic_rule(line: str) -> LogicRule:
        """Parse a logic rule (AND, OR, NOT)"""
        # Extract logic type
        logic_rule_match = re.match(r'^(AND|OR|NOT),\((.+)\),([^,]+)$', line)
        if not logic_rule_match:
            raise ValueError(f"Cannot extract action from logic rule: {line}")
        logic_type_str = logic_rule_match.group(1).upper().strip()
        logic_type = RuleType(logic_type_str)
        action = logic_rule_match.group(3).strip()
        # Try to convert action to enum
        try:
            action_enum = Action(action.upper())
            final_action = action_enum
        except ValueError:
            final_action = action
        conditions_str = logic_rule_match.group(2)
        conditions = ClashRuleParser._parse_logic_conditions(conditions_str)

        return LogicRule(
            logic_type=logic_type,
            conditions=conditions,
            action=final_action,
            raw_rule=line
        )

    @staticmethod
    def _parse_logic_conditions(conditions_str: str) -> List[ClashRule]:
        """Parse conditions within logic rules"""
        conditions = []

        # Simple parser for conditions like (DOMAIN,baidu.com),(NETWORK,UDP)
        # This is a basic implementation - more complex nested logic would need a proper parser
        condition_pattern = r'\(([^,]+),([^)]+)\)'
        matches = re.findall(condition_pattern, conditions_str)

        for rule_type_str, payload in matches:
            try:
                rule_type = RuleType(rule_type_str.upper())
                condition = ClashRule(
                    rule_type=rule_type,
                    payload=payload,
                    action="",  # Logic conditions don't have actions
                    raw_rule=f"{rule_type_str},{payload}"
                )
                conditions.append(condition)
            except ValueError:
                continue

        return conditions

    @staticmethod
    def action_string(action: Union[Action, str]) -> str:
        return action.value if isinstance(action, Action) else action

    @staticmethod
    def parse_rules(rules_text: str) -> List[Union[ClashRule, LogicRule, MatchRule]]:
        """Parse multiple rules from text, preserving order and priority"""
        rules = []
        lines = rules_text.strip().split('\n')

        for line in lines:
            rule = ClashRuleParser.parse_rule_line(line)
            if rule:
                rules.append(rule)

        return rules

    @staticmethod
    def validate_rule(rule: ClashRule) -> bool:
        """Validate a parsed rule"""
        try:
            # Basic validation based on rule type
            if rule.rule_type in [RuleType.IP_CIDR, RuleType.IP_CIDR6]:
                # Validate CIDR format
                return '/' in rule.payload

            elif rule.rule_type == RuleType.DST_PORT or rule.rule_type == RuleType.SRC_PORT:
                # Validate port number/range
                return rule.payload.isdigit() or '-' in rule.payload

            elif rule.rule_type == RuleType.NETWORK:
                # Validate network type
                return rule.payload.lower() in ['tcp', 'udp']

            elif rule.rule_type == RuleType.DOMAIN_REGEX or rule.rule_type == RuleType.PROCESS_PATH_REGEX:
                # Try to compile regex
                re.compile(rule.payload)
                return True

            return True

        except Exception:
            return False
