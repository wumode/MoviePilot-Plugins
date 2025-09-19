from typing import Any, Final, Optional, List, Literal, Dict, Tuple, Union
from urllib.parse import urlparse


class UtilsProvider:

    @staticmethod
    def filter_empty(original_dict: dict, empty: Optional[List[Any]] = None) -> dict:
        """过滤字典中的空值"""
        return {k: v for k, v in original_dict.items() if v not in (empty or [None, '', [], {}])}

    @staticmethod
    def get_url_domain(url: str) -> str:
        """从 url 中提取域名"""
        if not url:
            return ""
        parsed = urlparse(url)
        if not parsed.netloc:
            parsed = urlparse("https://" + url)
        return parsed.netloc

    @staticmethod
    def find_cycles(graph: Dict[Any, Any]) -> List[List[Any]]:
        """DFS 检测环，并记录路径"""
        visited = set()
        stack = []
        cycles = []

        def dfs(node):
            if node in stack:
                cycle_index = stack.index(node)
                cycles.append(stack[cycle_index:] + [node])
                return
            if node in visited:
                return

            visited.add(node)
            stack.append(node)
            for nei in graph.get(node, []):
                dfs(nei)
            stack.pop()

        for n in graph:
            if n not in visited:
                dfs(n)
        return cycles
