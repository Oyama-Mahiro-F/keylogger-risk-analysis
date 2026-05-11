# 键盘监听风险机理分析与防护验证

> 信息安全编程技术与实例开发 · 平时作业

---

## 项目简介

一个围绕键盘监听（Keylogging）安全风险的编程作业，用 Python 写了三个核心模块：

1. **风险模拟** — 模拟键盘 Hook 的行为特征，搞清楚键盘记录器到底是怎么工作的
2. **检测识别** — 从文件、进程、注册表、API 四个维度扫描系统，给出风险评分
3. **防护验证** — 实现三种防键盘监听的输入方案，对比各自的效果

代码量约 1300 行，10 个 Python 文件，外加一个 29 页的 PDF 报告。

---

## 目录结构

```
keylogger_risk_analysis/
├── main.py                     # 入口，调度三个阶段
├── requirements.txt
│
├── risk_simulation/            # 风险模拟
│   ├── key_hook.py             #   键盘 Hook 模拟器
│   └── logger.py               #   带窗口关联和敏感信息检测的记录器
│
├── detection/                  # 检测识别
│   ├── hook_detector.py        #   文件扫描 + API 签名检测
│   ├── process_scanner.py      #   进程行为分析
│   └── risk_scorer.py          #   四维度加权风险评分
│
├── protection/                 # 防护验证
│   ├── anti_hook.py            #   反 Hook 引擎 + 监控线程
│   └── secure_input.py         #   虚拟键盘 / 输入混淆 / 加密通道
│
└── output/                     # 运行产物
    ├── risk_analysis_report_*.json
    └── 键盘监听风险机理分析与防护验证程序_报告.pdf
```

---

## 怎么跑

```bash
cd keylogger_risk_analysis
pip install -r requirements.txt   # 不装也能跑，会自动降级
python main.py                    # 运行主程序
```

pynput 没装的话 Hook 模拟会降级为特征展示模式，psutil 没装的话进程扫描会用模拟数据，不会报错退出。

---

## 详细代码实现逻辑

### 一、整体架构与数据流

程序入口 `main.py::main()` 按三阶段流水线调度：

```
main()
 ├─ [阶段1] run_risk_simulation()   → hook 对象 + 运行统计
 ├─ [阶段2] run_detection()         → Hook报告 + 进程报告 + 风险评分
 ├─ [阶段3] run_protection()        → 防护引擎 + 安全输入结果
 └─ generate_final_report()         → JSON 汇总报告
```

每阶段有独立的 `print_section()` 标题输出，阶段间通过 Python 原生数据结构（dict/list/dataclass）传递结果，不依赖文件或数据库。阶段1产生的日志文件会在阶段2被 HookDetector 的文件系统扫描重新读取，形成"模拟→检测"的闭环。

**优雅降级机制**：`main()` 启动时检查 `pynput` 和 `psutil` 是否可用。pynput 缺失时阶段1跳过实际键盘监听、仅展示 API 签名和调用链；psutil 缺失时阶段2的 ProcessScanner 返回预置模拟数据。两个库都缺也能完整跑通三阶段，不会因 `ImportError` 崩溃。

---

### 二、风险模拟模块 (`risk_simulation/`)

#### 2.1 key_hook.py — 键盘 Hook 模拟器

**类结构**：

```
KeyboardHookSimulator
 ├── __init__(stealth_mode)    初始化状态变量
 ├── _on_press(key)            按键回调（pynput 事件线程中执行）
 ├── _on_release(key)          释放回调（空实现）
 ├── _flush_buffer()           将缓冲区刷盘
 ├── _run_listener(duration)   监听线程主循环
 ├── start(duration)           启动监听（创建 daemon 线程）
 ├── stop()                    停止监听并 flush 剩余缓冲
 ├── get_stats()               返回运行统计 dict
 └── cleanup() [staticmethod]  清除 .sys_cache 目录及日志
```

**`_on_press()` 实现逻辑**：

```
1. 尝试 key.char 获取可打印字符
2. 若为 None（如小键盘键、功能键）：
   a. 通过 key.vk 查 NUMPAD_VK_MAP（96-111 的虚拟键码）
      → 命中则输出 "[小键盘 X]" 可读标记
   b. 否则用 key.name 取功能键名（如 "<enter>", "<shift>"）
   c. 都不通才 fallback 到 str(key)
3. 构造 {"timestamp": ..., "key": ...} 条目
4. threading.Lock 保护下 append 到全局 LOG_BUFFER
5. len(LOG_BUFFER) >= 20 时自动触发 _flush_buffer()
```

**`_flush_buffer()` 实现逻辑**：

```
1. 加锁 → 取出 LOG_BUFFER 全部内容 → 清空 LOG_BUFFER → 释放锁
2. 创建 Path.home() / ".sys_cache" 目录（exist_ok=True）
3. 追加写 .idx.dat 文件，每行一条 JSON
4. except Exception: pass  —— 写盘失败静默吞异常，不抛给调用方
```

**全局状态**：`HOOK_ACTIVE`（bool）、`LOG_BUFFER`（list）、`BUFFER_LOCK`（threading.Lock）、`LOG_DIR`（Path）均为模块级变量，因此 `start()` 之后即使 hook 对象引用丢失，监听仍在后台持续运行且日志持续写入。

**小键盘支持**：`NUMPAD_VK_MAP` 字典映射了 VK_NUMPAD0-9（96-105）、VK_MULTIPLY（106）、VK_ADD（107）、VK_SEPARATOR（108）、VK_SUBTRACT（109）、VK_DECIMAL（110）、VK_DIVIDE（111）→ 可读字符串。

**KNOW_KEYLOGGER_SIGNATURES**：7 个 API 的 `{名称: 用途说明}` 字典，在阶段1开头直接遍历打印。

**`simulate_hook_api_calls()`**：返回 6 步调用链列表 `[(DLL, API, 参数), ...]`，模拟从状态键轮询到钩子注册到持续读取的完整攻击序列。参数使用了真实 Windows 虚拟键码（0x10=VK_SHIFT, 0x11=VK_CONTROL, 0x20=VK_SPACE）。

**`get_simulated_hook_signature()`**：返回 dict，聚合了 hook 类型、核心 DLL、相关 API 列表、文件特征列表、注册表路径，供阶段2的 HookDetector 做签名匹配参考。

#### 2.2 logger.py — 智能键盘记录器

**类结构**：

```
SmartKeyLogger
 ├── buffer: str               按键字符累积缓冲区
 ├── window_title: str          当前活动窗口标题
 ├── sensitive_matches: list    检测到的敏感信息告警
 ├── snapshots: list            定时快照列表
 ├── set_window_title(title)    更新窗口标题，检测到切换时写入缓冲区标记
 ├── feed_key(key_str)          喂入单个按键，返回敏感告警或 None
 ├── _scan_sensitive()          对缓冲区最近 500 字符做正则扫描
 ├── take_snapshot()            保存当前缓冲区快照
 └── get_risk_summary()         汇总所有统计数据
```

**`feed_key()` 实现逻辑**：

```
1. total_keystrokes++
2. 查 special_keys 映射表：
   Key.enter → \n,  Key.tab → \t,    Key.space → " "
   Key.backspace → <BS>,  Key.delete → <DEL>,  Key.esc → <ESC>
3. 其余 Key.xxx → <xxx>，普通字符直接追加
4. 调用 _scan_sensitive() 检查最近 500 字符
5. 命中则返回 alert dict，否则返回 None
```

**`SENSITIVE_PATTERNS`**：6 个预编译正则（`re.compile`）：
- `password_pattern`：匹配 password/passwd/pwd/密码/口令 关键词
- `credit_card_pattern`：匹配 16 位数字，支持空格/连字符分隔
- `id_card_pattern`：匹配 18 位中国身份证号（含出生日期校验和末位 X）
- `phone_pattern`：匹配 1[3-9]xxxxxxxxx 手机号
- `email_pattern`：匹配标准邮箱格式
- `ip_pattern`：匹配 IPv4 地址

---

### 三、检测识别模块 (`detection/`)

#### 3.1 hook_detector.py — Hook 检测引擎

**类结构**：

```
HookDetector
 ├── findings: list           检测发现项列表
 ├── risk_indicators: list    人类可读风险指标
 ├── scan_all()               执行全部检测 → 返回报告
 ├── _check_file_indicators()  文件系统嗅探
 ├── _check_hook_signatures()  Hook API 可用性检查（分发到平台实现）
 ├── _simulate_windows_hook_check()  Windows 平台 ctypes 检测
 ├── generate_report()         生成检测报告 dict
 └── _calculate_risk_level()   汇总风险等级
```

**`scan_all()` 调用流程**：

```
scan_all()
 ├─ _check_file_indicators()    扫描文件系统
 ├─ _check_hook_signatures()    检查 API 签名（非 Windows 则记录平台信息）
 └─ generate_report()           汇总并计算风险等级
```

**`_check_file_indicators()` 实现逻辑**：

```
1. 定义 3 个扫描根路径：~/.sys_cache, %TEMP%, %LOCALAPPDATA%/Temp
2. 对每个路径 os.walk() 递归遍历，深度超过 3 层则 continue
3. 文件名/目录名用 SUSPICIOUS_FILE_PATTERNS 的 5 个正则匹配：
   .*\.idx\.dat$ → "隐蔽按键日志文件"
   .*keylog.*\.(txt|bin|dat|log)$ → "键盘记录日志"
   .*\.sys_cache\\.* → "伪装系统缓存的日志目录"
   .*winlog\.dat$ → "伪装Windows日志文件"
   .*kl\.dat$ → "键盘记录器输出文件"
4. 目录命中 .*\.sys_cache$ → 高危（severity: "high"）
5. PermissionError → continue（无权限的目录静默跳过）
```

**`_simulate_windows_hook_check()` 实现逻辑**：

```
1. import ctypes
2. 对 HOOK_API_SIGNATURES 中 9 个 API 逐一：
   a. getattr(user32, api_name) → 成功则记入 (api_name, "user32.dll")
   b. 抛 AttributeError 则尝试 getattr(kernel32, api_name)
   c. 都失败则 continue
3. 发现 ≥3 个 API 时追加 finding，severity 为 "info"（存在≠恶意）
```

**`_calculate_risk_level()` 评分规则**：

```
score = high×30 + medium×15 + low×5 + info×1
score = min(score, 100)

≥60 → HIGH   （建议终止进程、清除文件、检查自启动）
≥30 → MEDIUM （建议排查进程、审查文件来源）
<30 → LOW    （保持常规监控）
```

#### 3.2 process_scanner.py — 进程行为扫描器

**类结构**：

```
ProcessScanner
 ├── scan_results: list         所有进程分析结果
 ├── suspicious_processes: list 可疑进程列表
 ├── scan()                     遍历全进程 → 逐进程分析 → 生成报告
 ├── _analyze_process(proc)     单进程四维分析
 ├── _is_suspicious_ip(ip)      IP 黑名单匹配
 ├── _simulate_scan()           psutil 不可用时的模拟数据
 └── _generate_report()         按 risk_score 分高低中三档汇总
```

**`scan()` 调用流程**：

```
scan()
 ├─ 若 HAS_PSUTIL=False → _simulate_scan() → 返回预置模拟数据
 ├─ psutil.process_iter(['pid', 'name', 'exe', 'cmdline'])
 │   └─ 对每个进程调用 _analyze_process(proc)
 │       ├─ 不抛异常：追加到 scan_results，suspicious 则额外入 suspicious_processes
 │       └─ NoSuchProcess/AccessDenied/PermissionError → continue
 └─ _generate_report()
```

**`_analyze_process()` 四维打分逻辑**：

```
维度1 — 进程名可疑（+20 分）：
  regex 匹配 keylog/hook/spy/capture/logger/monitor
  命中一条即触发 suspicious 标记

维度2 — CPU 使用率异常（+5 分）：
  proc.cpu_percent(interval=0) > 80% → 异常
  （interval=0 获取缓存值，避免阻塞等待）

维度3 — 文件句柄异常（+10 分）：
  len(proc.open_files()) > 300 → 异常
  （300 是考虑到现代浏览器/IDE 的正常基线）

维度4 — 可疑网络连接（+15 分）：
  遍历 proc.connections()，对 ESTABLISHED 连接的目标 IP
  调用 _is_suspicious_ip() 做黑名单匹配（示例规则 185.* 和 91.234.*）

风险判定：risk_score ≥ 15 → suspicious=True
```

**`_simulate_scan()` 模拟数据**：psutil 不可用时返回 4 个预置进程，其中两个可疑（PID 8888 冒充 svchost.exe 位于 C:\Users\Public\，PID 9999 冒充 winlogon.exe 位于 C:\Windows\Temp\ 且"注册了 WH_KEYBOARD_LL 钩子"）。

#### 3.3 risk_scorer.py — 风险评分引擎

**类结构**：

```
RiskLevel(Enum)
 ├── LOW      = (低风险, 0, 29, green)
 ├── MEDIUM   = (中风险, 30, 59, yellow)
 ├── HIGH     = (高风险, 60, 79, orange)
 └── CRITICAL = (严重风险, 80, 100, red)

RiskScorer
 ├── RULES: dict                      四维度规则集（类变量）
 ├── scores/dict, details/dict        评分中间结果
 ├── evaluate(file/process/persistence/api_findings)  主入口
 ├── _score_dimension(dimension, findings)            单维度评分
 ├── _calculate_match(dimension, findings, indicator_desc)  匹配度计算
 ├── _determine_risk_level(score)      等级判定
 ├── _generate_report()                生成完整报告
 └── _get_recommendation()             按等级给出处置建议
```

**`RULES` 规则集结构**（类变量，18 个指标）：

```python
{
    "file_system": {       # 权重 0.35
        "indicators": [    # 5 个指标，各含描述 + 预设分值
            ("隐蔽按键日志文件", 25), ("伪装系统目录", 30),
            ("文件近期被写入", 20), ("多个可疑备份", 15), ("权限异常", 10)
        ]
    },
    "process_behavior": {  # 权重 0.30, 5 个指标
    },
    "persistence": {       # 权重 0.20, 4 个指标
    },
    "api_signature": {     # 权重 0.15, 4 个指标
    }
}
```

**`evaluate()` 主流程**：

```
evaluate(file_findings, process_findings, persistence_findings, api_findings)
 ├─ _score_dimension("file_system", file_findings)
 ├─ _score_dimension("process_behavior", process_findings)
 ├─ _score_dimension("persistence", persistence_findings)
 ├─ _score_dimension("api_signature", api_findings)
 ├─ total_score = Σ(维度分 × 权重)   # 四维加权求和
 ├─ total_score = min(total_score, 100)  # 封顶 100
 ├─ _determine_risk_level(total_score)   # 判定等级
 └─ _generate_report()
```

**`_score_dimension()` 单维度评分逻辑**：

```
1. 取该维度全部指标，计算 max_possible = Σ(各指标预设分值)
2. 对每个指标：
   a. _calculate_match(findings, indicator_desc) 计算匹配率 [0.0-1.0]
   b. earned = 预设分值 × 匹配率
   c. 记录匹配详情
3. normalized = (实际得分 / max_possible) × 100   # 归一化到 0-100
4. 存入 self.scores[dimension]
```

**`_calculate_match()` 匹配度算法**（词集 Jaccard 相似度）：

```
1. 对 indicator_desc 做分词（英文单词 + 中文 bigram）→ indicator_tokens
2. 遍历所有 findings：
   a. 取 finding["description"] 做同样分词 → finding_tokens
   b. intersection = indicator_tokens ∩ finding_tokens
   c. union = indicator_tokens ∪ finding_tokens
   d. jaccard = len(intersection) / len(union)
   e. 若 jaccard ≥ 0.15（有效命中阈值）：
      match = severity_weight × min(jaccard × 3, 1.0)
   f. 若无 findings → 返回 0.0
3. 返回 mean(各 finding 的 match 值)，封顶 1.0
```

**等级判定与处置建议**：

| 分数区间 | 等级 | 颜色 | 建议 |
|---------|------|------|------|
| 0-29 | LOW | green | 保持常规安全策略 |
| 30-59 | MEDIUM | yellow | 排查进程行为、检查异常文件、加强监控 |
| 60-79 | HIGH | orange | 排查终止可疑进程、检查自启动项、审查文件变更、启用加密保护 |
| 80-100 | CRITICAL | red | 立即终止进程、隔离主机、清除持久化、修改密码、启动安全审计 |

---

### 四、防护验证模块 (`protection/`)

#### 4.1 anti_hook.py — 反 Hook 防护引擎

**类结构**：

```
AntiHookProtection
 ├── protection_active: bool        防护开关
 ├── hook_attempts_blocked: int     阻止计数
 ├── warnings: list                 告警列表
 ├── _monitor_thread: Thread        后台监控线程引用
 ├── enable_protection()            启用防护 + 启动监控线程
 ├── disable_protection()           停用防护
 ├── _start_monitoring()            创建 daemon 监控线程
 ├── _monitor_loop()                监控主循环（2 秒轮询）
 ├── _check_for_new_hooks()         检查新 Hook 注册（占位，真实场景调 API）
 ├── detect_hook_attempt()          模拟检测到 Hook 尝试 → 记录 warning
 ├── get_protection_status()        返回当前防护状态
 ├── sanitize_keyboard_input() [static]  输入安全化（过滤空字节）
 └── generate_protection_report() [static]  返回防护策略 + 最佳实践
```

**`enable_protection()` 调用链**：

```
enable_protection()
 ├─ protection_active = True
 ├─ _start_monitoring()
 │   └─ threading.Thread(target=_monitor_loop, daemon=True).start()
 │       └─ while protection_active:
 │           ├─ _check_for_new_hooks()   # 调 Windows API 枚举 Hook 链（占位）
 │           └─ time.sleep(2)            # 2 秒轮询间隔
 └─ 返回 {"status": "activated", "protections": [...]}
```

**`generate_protection_report()` 返回结构**：

```
{
    "strategies": [5 种防护策略，各含 name/description/effectiveness/overhead],
    "best_practices": [7 条最佳实践]
}
```

5 种策略：API Hook 检测、行为基线分析、输入通道加密、可信进程白名单、内核级输入隔离。
7 条最佳实践：安全桌面、高 UAC、审计自启动、保持更新、不运行不可信程序、双因素认证、生物识别。

#### 4.2 secure_input.py — 安全输入引擎

**数据结构**：

```python
@dataclass
class InputProtectionResult:
    method: str               # 方案名称
    original_input: str       # 原始输入
    protected_output: str     # 保护后的输出（或原始密码）
    protection_level: str     # low/medium/high/very_high
    overhead_ms: float        # 性能开销（毫秒）
    keylogger_resistant: bool # 是否抗键盘记录
    notes: str                # 说明
```

**`SecureInputEngine` 类结构**：

```
SecureInputEngine
 ├── protection_results: List[InputProtectionResult]
 ├── virtual_keyboard_input(password)     方案1
 ├── obfuscated_input(password)           方案2
 ├── encrypted_channel_input(password)    方案3
 ├── compare_all_methods(password)        依次执行三方案 → 返回列表
 └── simulate_keylogger_attempt(result) [staticmethod]  模拟窃取测试
```

**方案1 — 虚拟键盘输入**：

```
virtual_keyboard_input(password)
1. 对每个字符映射到模拟屏幕坐标 (100 + i%10 × 50, 300 + i//10 × 50)
2. original_input = password
3. 返回 InputProtectionResult(
     method="虚拟键盘输入",
     protection_level="high",
     keylogger_resistant=True,
     notes="按键不经过物理键盘通道，传统Hook无法捕获；缺点：屏幕截图/鼠标Hook可绕过"
   )
```

**方案2 — 输入混淆**：

```
obfuscated_input(password)
1. noise_keys = ['\b', '\x1b', '\t', random_letter]
2. 遍历 password 每个字符：
   a. random() < 0.4 → 40% 概率插入噪声字符
   b. 噪声若不是退格/ESC → 追加 \b 来"删除"噪声（保证最终字符串正确）
   c. 追加原始字符
3. 返回 InputProtectionResult(
     method="输入混淆",
     protection_level="medium",
     keylogger_resistant=True,
     notes="键盘记录器记录总长XX字符，难以区分噪声与真实输入；缺点：高级记录器可分析退格序列还原"
   )
```

**方案3 — 加密通道输入**：

```
encrypted_channel_input(password)
1. raw_entropy = os.urandom(32)                    # 32 字节随机种子
2. session_key = hashlib.sha256(raw_entropy).digest()  # SHA-256 派生 32 字节密钥
3. 对 password 每个字符：
   encrypted_byte = ord(ch) ^ session_key[i % 32]   # XOR 流加密
4. encrypted_str = base64.b64encode(encrypted_bytes)  # Base64 可展示编码
5. 返回 InputProtectionResult(
     method="加密通道输入",
     protection_level="very_high",
     keylogger_resistant=True
   )
```

> 注：演示用途使用 XOR 流加密，生产环境建议 AES-GCM 等认证加密方案。

**`compare_all_methods()` 调用流程**：

```
compare_all_methods(password)
 ├─ self.protection_results = []
 ├─ virtual_keyboard_input(password)    → append
 ├─ obfuscated_input(password)          → append
 ├─ encrypted_channel_input(password)   → append
 └─ return self.protection_results
```

**`simulate_keylogger_attempt()` 模拟结果**：

| 方案 | 键盘记录器捕获结果 |
|------|-------------------|
| 虚拟键盘输入 | `[空]` — 无物理按键事件 |
| 输入混淆 | 如 `'a\bx\bP@sw0r\bd...'` — 混淆序列 |
| 加密通道输入 | 如 `'ygDUR6/FkGaSS3be4mqo...'` — 纯密文 |

---

## 一些实现上的选择

**为什么用 Python 而不是 C/C++？**

这个作业的重点是理解风险机理和写报告，不是做一个能实际对抗杀软的工具。Python 写起来快，库丰富，出报告也方便。1300 行 Python 可以把三个模块都讲清楚，同等工作量用 C 可能连 Hook 检测都没写完。

**为什么没装 pynput 也能跑？**

作业最终要交 PDF 报告给老师审阅，不能假设老师的电脑上装了 pynput 和 psutil。程序启动时检查依赖，缺什么就自动切到模拟模式——pynput 没了就展示 API 签名和调用链，psutil 没了就用预置的模拟数据。零配置就能跑，老师不需要折腾环境。

**三层架构是不是过度设计了？**

考虑过把所有功能写在一个文件里（更简单），但三个阶段的输入输出都不一样，揉在一起反而不清楚。分开后每个模块可以独立测试，而且报告里"代码开发"那章按模块讲也更顺。

---

## 项目数据

| 项目 | 数值 |
|------|------|
| Python 文件 | 8 个 |
| 核心类 | 8 个 |
| 总代码量 | ~1,300 行 |
| Hook API 签名 | 7 个（hook_detector 额外 9 个） |
| 风险评分指标 | 18 个（4 维度） |
| 敏感信息正则 | 6 种 |
| 防护方案 | 3 种 |
| PDF 报告 | 29 页 |

---

## 运行示例

```
╔══════════════════════════════════════════════════════════════╗
║     键盘监听风险机理分析与防护验证系统                          ║
╚══════════════════════════════════════════════════════════════╝

[系统初始化] 检查依赖... pynput [X] psutil [OK]

============================================================
  第一阶段：风险机理模拟
============================================================
[1.1] 已知键盘Hook相关API签名: 7 个
[1.2] API调用链: 6 次调用
[1.3] Hook行为特征: WH_KEYBOARD_LL

============================================================
  第二阶段：风险检测与评分
============================================================
[2.1] Hook检测器: 发现 1 个问题，风险评分 15/100
[2.2] 进程扫描器: 扫描 446 个进程，2 个可疑
[2.3] 综合风险评分: 52.1/100 [中风险]
  文件系统指标 (35%): 67.0/100
  进程行为指标 (30%): 65.0/100
  持久化机制指标 (20%):  9.0/100
  API调用特征指标 (15%): 49.0/100

============================================================
  第三阶段：防护方案验证
============================================================
[3.1] 反Hook防护引擎: 已激活
[3.2] 安全输入方案对比:
  虚拟键盘输入   → 键盘记录器结果: [空]
  输入混淆       → 键盘记录器结果: 'a\bx\bP@sw0r\bd...'
  加密通道输入   → 键盘记录器结果: 'a5LHud/TFPWRn...' (密文)
[3.3] 防护建议: 7 条

────────────────────────────────────────────────────────────
  综合风险等级: 中风险
  综合风险得分: 52.1/100
────────────────────────────────────────────────────────────
```

---

## 文件清单

| 文件 | 说明 |
|------|------|
| `main.py` | 主程序入口，三阶段流程调度 |
| `risk_simulation/key_hook.py` | Hook 模拟器 + API 签名库 |
| `risk_simulation/logger.py` | 窗口关联 + 敏感信息检测 |
| `detection/hook_detector.py` | 文件扫描 + API 检查 |
| `detection/process_scanner.py` | 进程行为四维分析 |
| `detection/risk_scorer.py` | 四维度加权评分引擎 |
| `protection/anti_hook.py` | 反 Hook 引擎 + 防护建议 |
| `protection/secure_input.py` | 三种安全输入方案 |
