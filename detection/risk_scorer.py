"""
风险评分引擎

基于多维度规则对键盘监听威胁进行量化评分：
- 文件系统指标 (权重35%)
- 进程行为指标 (权重30%)
- 注册表/持久化指标 (权重20%)
- API调用特征 (权重15%)

评分区间: 0-100
  - 0-29: 低风险 (绿色)
  - 30-59: 中风险 (黄色)
  - 60-79: 高风险 (橙色)
  - 80-100: 严重风险 (红色)
"""

import re
from datetime import datetime
from enum import Enum


class RiskLevel(Enum):
    LOW = ("低风险", 0, 29, "green")
    MEDIUM = ("中风险", 30, 59, "yellow")
    HIGH = ("高风险", 60, 79, "orange")
    CRITICAL = ("严重风险", 80, 100, "red")


class RiskScorer:
    """
    风险评分引擎
    使用加权评分模型对键盘监听威胁进行量化评估
    """

    # 评分规则集
    RULES = {
        "file_system": {
            "weight": 0.35,
            "indicators": [
                # (指标描述, 分值, 检测函数)
                ("存在隐蔽按键日志文件 (.idx.dat, keylog.*)", 25, None),
                ("日志存储在伪装系统目录 (.sys_cache)", 30, None),
                ("日志文件近期被写入 (<1小时)", 20, None),
                ("存在多个可疑日志备份", 15, None),
                ("日志文件权限异常 (所有人可读)", 10, None),
            ],
        },
        "process_behavior": {
            "weight": 0.30,
            "indicators": [
                ("进程导入了SetWindowsHookEx API", 30, None),
                ("频繁调用GetAsyncKeyState", 25, None),
                ("进程伪装为系统进程名但位于非系统目录", 20, None),
                ("无数字签名的进程以管理员权限运行", 15, None),
                ("进程网络连接指向可疑C2服务器", 10, None),
            ],
        },
        "persistence": {
            "weight": 0.20,
            "indicators": [
                ("注册了Run/RunOnce自启动项", 35, None),
                ("创建了计划任务持久化", 30, None),
                ("添加了Windows服务", 20, None),
                ("修改了启动文件夹", 15, None),
            ],
        },
        "api_signature": {
            "weight": 0.15,
            "indicators": [
                ("检测到WH_KEYBOARD_LL钩子类型", 40, None),
                ("检测到WH_KEYBOARD钩子类型", 35, None),
                ("检测到GetAsyncKeyState轮询模式", 15, None),
                ("检测到RegisterRawInputDevices调用", 10, None),
            ],
        },
    }

    def __init__(self):
        self.scores = {}
        self.details = {}
        self.total_score = 0
        self.risk_level = RiskLevel.LOW
        self.evaluation_time = None

    def evaluate(self, file_findings=None, process_findings=None,
                 persistence_findings=None, api_findings=None):
        """
        执行完整风险评估

        参数:
            file_findings: 文件系统检测发现
            process_findings: 进程行为检测发现
            persistence_findings: 持久化机制检测发现
            api_findings: API调用特征检测发现
        """
        self.evaluation_time = datetime.now()
        self.scores = {}
        self.details = {}

        # 对每个维度计算加权得分
        self._score_dimension("file_system", file_findings or [])
        self._score_dimension("process_behavior", process_findings or [])
        self._score_dimension("persistence", persistence_findings or [])
        self._score_dimension("api_signature", api_findings or [])

        # 计算总分
        self.total_score = sum(
            self.scores.get(dim, 0) * self.RULES[dim]["weight"]
            for dim in self.RULES
        )

        self.total_score = round(min(self.total_score, 100), 1)
        self.risk_level = self._determine_risk_level(self.total_score)

        return self._generate_report()

    def _score_dimension(self, dimension, findings):
        """对单个维度进行评分"""
        rules = self.RULES[dimension]["indicators"]
        max_possible = sum(r[1] for r in rules)

        score = 0
        matched = []

        for desc, points, _ in rules:
            # 根据findings数量模拟匹配
            # 在真实系统中，这里会调用检测函数
            match_percentage = self._calculate_match(dimension, findings, desc)
            if match_percentage > 0:
                earned = points * match_percentage
                score += earned
                matched.append({
                    "indicator": desc,
                    "max_points": points,
                    "earned": round(earned, 1),
                    "match_rate": round(match_percentage * 100, 1),
                })

        # 归一化到0-100
        normalized = (score / max_possible * 100) if max_possible > 0 else 0
        self.scores[dimension] = min(round(normalized, 1), 100)
        self.details[dimension] = matched

    def _calculate_match(self, dimension, findings, indicator_desc):
        """
        计算某个指标与findings的匹配度，返回 0.0-1.0 之间的匹配率。

        使用词集 Jaccard 相似度 + 严重程度加权，比简单子串匹配
        能更好地区分"检测到WH_KEYBOARD_LL钩子"与"检测到钩子类型"之间的
        真实语义关联程度。
        """
        if not findings:
            return 0.0

        severity_map = {"high": 1.0, "medium": 0.6, "low": 0.3, "info": 0.1}

        def _tokenize(text):
            """提取中文2-gram和英文单词"""
            tokens = set()
            clean = re.sub(r'[()（）,.，。、\s]+', ' ', text).strip().lower()
            words = clean.split()
            for w in words:
                tokens.add(w)
            # 中文2-gram
            for i in range(len(clean) - 1):
                bigram = clean[i:i + 2]
                if all('一' <= c <= '鿿' for c in bigram):
                    tokens.add(bigram)
            return tokens

        indicator_tokens = _tokenize(indicator_desc)
        if not indicator_tokens:
            return 0.0

        total_match = 0.0
        count = 0

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            desc = finding.get("description", "")
            severity = finding.get("severity", "low")
            finding_tokens = _tokenize(desc)
            if not finding_tokens:
                continue

            intersection = indicator_tokens & finding_tokens
            union = indicator_tokens | finding_tokens
            jaccard = len(intersection) / len(union) if union else 0.0

            # Jaccard ≥ 0.15 视为有效命中，比例越高匹配越强
            if jaccard >= 0.15:
                total_match += severity_map.get(severity, 0.3) * min(jaccard * 3, 1.0)
                count += 1

        if count == 0:
            return 0.0

        return min(total_match / count, 1.0)

    def _determine_risk_level(self, score):
        """确定风险等级"""
        for level in RiskLevel:
            _, low, high, _ = level.value
            if low <= score <= high:
                return level
        return RiskLevel.LOW

    def _generate_report(self):
        """生成风险评估报告"""
        return {
            "evaluation_time": self.evaluation_time.isoformat() if self.evaluation_time else None,
            "total_score": self.total_score,
            "risk_level": self.risk_level.value[0],
            "risk_color": self.risk_level.value[3],
            "dimension_scores": {
                "文件系统指标": {
                    "score": self.scores.get("file_system", 0),
                    "weight": "35%",
                },
                "进程行为指标": {
                    "score": self.scores.get("process_behavior", 0),
                    "weight": "30%",
                },
                "持久化机制指标": {
                    "score": self.scores.get("persistence", 0),
                    "weight": "20%",
                },
                "API调用特征指标": {
                    "score": self.scores.get("api_signature", 0),
                    "weight": "15%",
                },
            },
            "details": self.details,
            "risk_bar": "█" * int(self.total_score / 5) + "░" * (20 - int(self.total_score / 5)),
            "recommendation": self._get_recommendation(),
        }

    def _get_recommendation(self):
        """根据风险等级生成建议"""
        level = self.risk_level

        if level == RiskLevel.CRITICAL:
            return (
                "[严重] 检测到严重的键盘监听威胁，建议立即采取以下措施:\n"
                "  1. 立即终止可疑进程\n"
                "  2. 隔离受影响主机\n"
                "  3. 检查并清除持久化机制\n"
                "  4. 修改所有已输入的密码\n"
                "  5. 启动安全审计"
            )
        elif level == RiskLevel.HIGH:
            return (
                "[高风险] 检测到明显的键盘监听威胁迹象，建议:\n"
                "  1. 排查并终止可疑进程\n"
                "  2. 检查自启动项\n"
                "  3. 审查近期的文件变更\n"
                "  4. 启用输入加密保护"
            )
        elif level == RiskLevel.MEDIUM:
            return (
                "[中风险] 检测到可疑的键盘监听指标，建议:\n"
                "  1. 进一步排查进程行为\n"
                "  2. 检查异常文件\n"
                "  3. 加强安全监控"
            )
        else:
            return (
                "[低风险] 未检测到明确的键盘监听威胁，建议保持常规安全策略。"
            )


# ============================
# 便捷函数
# ============================
def quick_risk_score(file_findings, process_findings, persistence_findings, api_findings):
    """快速风险评分"""
    scorer = RiskScorer()
    return scorer.evaluate(file_findings, process_findings, persistence_findings, api_findings)
