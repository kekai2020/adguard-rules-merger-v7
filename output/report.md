# AdGuard Rules Merger V7 — 规则分析报告

> 内容版本 2106c73078b3 | 源：17/17

## 一、概览

| 指标 | 数值 |
|------|------|
| Block 规则 | 2,536,859 |
| Allow 白名单 | 104 |
| 综合去重率 | 25.0% |
| 聚合精简 | 45,389 |
| 冲突消解 | 6 |
| 带 $ 修饰符规则 | 5 |
| 总耗时 | — |

## 二、优化流水线

| 阶段 | 规则数 | 本阶段减少 |
|------|--------|-----------|
| 原始规则（Raw） | 3,381,454 | - |
| 去重后（精确 795,878 / 规范化 3,212 / 正则 0） | 2,582,364 | -799,090 |
| 聚合后（精确 45,387 / 通配符 2 / 升级 0） | 2,536,975 | -45,389 |
| 冲突消解后 | 2,536,963 | -6 |

## 三、规则类型与类别分布

### 规则类型

| 类型 | 数量 |
|------|------|
| domain | 2,536,828 |
| ip | 74 |
| regex | 61 |

### 类别分布（Block）

| 类别 | 数量 |
|------|------|
| malware | 1,648,236 |
| other | 527,455 |
| ads | 308,755 |
| phishing | 51,883 |
| tracking | 384 |
| mining | 146 |

## 四、按源贡献分析（独占 vs 共享）

> 统计覆盖最终输出规则（含正则规则）。输出覆盖 = 该源参与的最终规则数（独占+共享）；覆盖率 = 输出覆盖/原始规则；独占率 = 独占/输出覆盖。

| 源 | 原始规则 | 输出覆盖 | 覆盖率 | 独占规则 | 与他源共享 | 独占率 |
|------|---------|---------|--------|---------|-----------|--------|
| HaGeZi's Threat Intelligence Feeds | 1,650,046 | 1,647,193 | 99.8% | 1,301,812 | 345,381 | 79.0% |
| HaGeZi's Gambling Blocklist | 703,816 | 703,430 | 99.9% | 526,124 | 177,306 | 74.8% |
| HaGeZi's Ultimate Blocklist | 289,814 | 286,596 | 98.9% | 112,771 | 173,825 | 39.3% |
| Phishing Army | 146,193 | 122,541 | 83.8% | 44,654 | 77,887 | 36.4% |
| CHN: AdRules DNS List | 212,117 | 207,747 | 97.9% | 9,181 | 198,566 | 4.4% |
| CHN: anti-AD | 102,112 | 101,372 | 99.3% | 7,444 | 93,928 | 7.3% |
| AdGuard DNS filter | 191,504 | 188,728 | 98.6% | 4,813 | 183,915 | 2.6% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 16,606 | 15,462 | 93.1% | 1,731 | 13,731 | 11.2% |
| ShadowWhisperer's Dating List | 1,438 | 1,438 | 100.0% | 1,332 | 106 | 92.6% |
| Malicious URL Blocklist (URLHaus) | 2,117 | 1,991 | 94.0% | 670 | 1,321 | 33.7% |
| Stalkerware Indicators List | 929 | 495 | 53.3% | 191 | 304 | 38.6% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 100.0% | 57 | 0 | 100.0% |
| OISD Blocklist Small | 62,171 | 60,345 | 97.1% | 7 | 60,338 | 0.0% |
| Scam Blocklist by DurableNapkin | 909 | 905 | 99.6% | 4 | 901 | 0.4% |
| NoCoin Filter List | 312 | 269 | 86.2% | 3 | 266 | 1.1% |
| HaGeZi's Windows/Office Tracker Blocklist | 395 | 387 | 98.0% | 1 | 386 | 0.3% |
| AWAvenue Ads Rule | 918 | 747 | 81.4% | 0 | 747 | 0.0% |

## 五、源间重复矩阵（两两重复规则数 + 重复率）

> 每格 `共同规则数 (重复率%)`，重复率 = Jaccard = 共同/并集（对称）；对角线为该源输出覆盖数。颜色：🟥≥80% 🟧50–80% 🟨20–50% 🟩<20%（含 0）

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **1** | **1,647,193** | 🟩 176,272 (8.1%) | 🟩 106,445 (5.8%) | 🟩 33,418 (1.8%) | 🟩 31,048 (1.7%) | 🟩 72,554 (4.3%) | 🟩 23,137 (1.3%) | 🟩 24,365 (1.4%) | 🟩 8,712 (0.5%) | 🟩 1,159 (0.1%) | 🟩 34 (0.0%) | 🟩 839 (0.1%) | 🟩 20 (0.0%) | 🟩 296 (0.0%) | 🟩 3 (0.0%) | 🟩 123 (0.0%) | · |
| **2** | 🟩 176,272 (8.1%) | **703,430** | 🟩 2,297 (0.2%) | 🟩 488 (0.1%) | 🟩 440 (0.0%) | 🟩 156 (0.0%) | 🟩 234 (0.0%) | 🟩 161 (0.0%) | 🟩 34 (0.0%) | 🟩 6 (0.0%) | · | 🟩 4 (0.0%) | · | 🟩 2 (0.0%) | · | 🟩 1 (0.0%) | · |
| **3** | 🟩 106,445 (5.8%) | 🟩 2,297 (0.2%) | **286,596** | 🟨 86,477 (21.2%) | 🟨 80,442 (20.4%) | 🟩 14,003 (3.5%) | 🟨 65,559 (20.3%) | 🟩 56,518 (19.5%) | 🟩 1,933 (0.6%) | 🟩 1,052 (0.4%) | 🟩 86 (0.0%) | 🟩 359 (0.1%) | 🟩 727 (0.3%) | 🟩 80 (0.0%) | 🟩 384 (0.1%) | 🟩 140 (0.0%) | · |
| **4** | 🟩 33,418 (1.8%) | 🟩 488 (0.1%) | 🟨 86,477 (21.2%) | **207,747** | 🟧 176,077 (79.9%) | 🟩 42 (0.0%) | 🟨 87,434 (39.4%) | 🟨 56,546 (26.7%) | 🟩 30 (0.0%) | 🟩 8 (0.0%) | 🟩 37 (0.0%) | 🟩 901 (0.4%) | 🟩 555 (0.3%) | 🟩 3 (0.0%) | 🟩 117 (0.1%) | 🟩 80 (0.0%) | · |
| **5** | 🟩 31,048 (1.7%) | 🟩 440 (0.0%) | 🟨 80,442 (20.4%) | 🟧 176,077 (79.9%) | **188,728** | 🟩 22 (0.0%) | 🟨 78,018 (36.8%) | 🟨 55,994 (29.0%) | 🟩 24 (0.0%) | 🟩 3 (0.0%) | 🟩 32 (0.0%) | 🟩 23 (0.0%) | 🟩 246 (0.1%) | 🟩 2 (0.0%) | 🟩 26 (0.0%) | 🟩 43 (0.0%) | · |
| **6** | 🟩 72,554 (4.3%) | 🟩 156 (0.0%) | 🟩 14,003 (3.5%) | 🟩 42 (0.0%) | 🟩 22 (0.0%) | **122,541** | 🟩 9 (0.0%) | 🟩 9 (0.0%) | 🟩 12,784 (10.2%) | 🟩 9 (0.0%) | · | 🟩 5 (0.0%) | · | · | · | · | · |
| **7** | 🟩 23,137 (1.3%) | 🟩 234 (0.0%) | 🟨 65,559 (20.3%) | 🟨 87,434 (39.4%) | 🟨 78,018 (36.8%) | 🟩 9 (0.0%) | **101,372** | 🟨 42,009 (35.1%) | 🟩 23 (0.0%) | 🟩 504 (0.5%) | 🟩 25 (0.0%) | 🟩 9 (0.0%) | 🟩 713 (0.7%) | 🟩 5 (0.0%) | 🟩 69 (0.1%) | 🟩 258 (0.3%) | · |
| **8** | 🟩 24,365 (1.4%) | 🟩 161 (0.0%) | 🟩 56,518 (19.5%) | 🟨 56,546 (26.7%) | 🟨 55,994 (29.0%) | 🟩 9 (0.0%) | 🟨 42,009 (35.1%) | **60,345** | 🟩 12 (0.0%) | 🟩 5 (0.0%) | 🟩 23 (0.0%) | 🟩 13 (0.0%) | 🟩 695 (1.2%) | 🟩 1 (0.0%) | 🟩 26 (0.0%) | 🟩 49 (0.1%) | · |
| **9** | 🟩 8,712 (0.5%) | 🟩 34 (0.0%) | 🟩 1,933 (0.6%) | 🟩 30 (0.0%) | 🟩 24 (0.0%) | 🟩 12,784 (10.2%) | 🟩 23 (0.0%) | 🟩 12 (0.0%) | **15,462** | 🟩 10 (0.1%) | · | 🟩 4 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 2 (0.0%) | · |
| **10** | 🟩 1,159 (0.1%) | 🟩 6 (0.0%) | 🟩 1,052 (0.4%) | 🟩 8 (0.0%) | 🟩 3 (0.0%) | 🟩 9 (0.0%) | 🟩 504 (0.5%) | 🟩 5 (0.0%) | 🟩 10 (0.1%) | **1,991** | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | · | · |
| **11** | 🟩 34 (0.0%) | · | 🟩 86 (0.0%) | 🟩 37 (0.0%) | 🟩 32 (0.0%) | · | 🟩 25 (0.0%) | 🟩 23 (0.0%) | · | · | **1,438** | 🟩 2 (0.1%) | · | · | · | · | · |
| **12** | 🟩 839 (0.1%) | 🟩 4 (0.0%) | 🟩 359 (0.1%) | 🟩 901 (0.4%) | 🟩 23 (0.0%) | 🟩 5 (0.0%) | 🟩 9 (0.0%) | 🟩 13 (0.0%) | 🟩 4 (0.0%) | 🟩 1 (0.0%) | 🟩 2 (0.1%) | **905** | · | · | · | 🟩 1 (0.1%) | · |
| **13** | 🟩 20 (0.0%) | · | 🟩 727 (0.3%) | 🟩 555 (0.3%) | 🟩 246 (0.1%) | · | 🟩 713 (0.7%) | 🟩 695 (1.2%) | 🟩 1 (0.0%) | · | · | · | **747** | 🟩 1 (0.1%) | 🟩 6 (0.5%) | · | · |
| **14** | 🟩 296 (0.0%) | 🟩 2 (0.0%) | 🟩 80 (0.0%) | 🟩 3 (0.0%) | 🟩 2 (0.0%) | · | 🟩 5 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | · | 🟩 1 (0.1%) | **495** | · | · | · |
| **15** | 🟩 3 (0.0%) | · | 🟩 384 (0.1%) | 🟩 117 (0.1%) | 🟩 26 (0.0%) | · | 🟩 69 (0.1%) | 🟩 26 (0.0%) | · | · | · | · | 🟩 6 (0.5%) | · | **387** | · | · |
| **16** | 🟩 123 (0.0%) | 🟩 1 (0.0%) | 🟩 140 (0.0%) | 🟩 80 (0.0%) | 🟩 43 (0.0%) | · | 🟩 258 (0.3%) | 🟩 49 (0.1%) | 🟩 2 (0.0%) | · | · | 🟩 1 (0.1%) | · | · | · | **269** | · |
| **17** | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | **57** |

**源编号对照**（按输出覆盖降序）

| # | 源 | 输出覆盖 |
|---|---|----------|
| 1 | HaGeZi's Threat Intelligence Feeds | 1,647,193 |
| 2 | HaGeZi's Gambling Blocklist | 703,430 |
| 3 | HaGeZi's Ultimate Blocklist | 286,596 |
| 4 | CHN: AdRules DNS List | 207,747 |
| 5 | AdGuard DNS filter | 188,728 |
| 6 | Phishing Army | 122,541 |
| 7 | CHN: anti-AD | 101,372 |
| 8 | OISD Blocklist Small | 60,345 |
| 9 | Phishing URL Blocklist (PhishTank and OpenPhish) | 15,462 |
| 10 | Malicious URL Blocklist (URLHaus) | 1,991 |
| 11 | ShadowWhisperer's Dating List | 1,438 |
| 12 | Scam Blocklist by DurableNapkin | 905 |
| 13 | AWAvenue Ads Rule | 747 |
| 14 | Stalkerware Indicators List | 495 |
| 15 | HaGeZi's Windows/Office Tracker Blocklist | 387 |
| 16 | NoCoin Filter List | 269 |
| 17 | HaGeZi's DNS Rebind Protection | 57 |

### 源间重复 Top 20（双向覆盖率明细）

> 每对源共同拥有的规则数；覆盖率 = 共同规则数 / 该源输出覆盖数。

| 源 A | 源 B | 共同规则数 | 重复率 | A 覆盖率 | B 覆盖率 |
|------|------|-----------|--------|---------|---------|
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Gambling Blocklist | 176,272 | 🟩 8.1% | 10.7% | 25.1% |
| AdGuard DNS filter | CHN: AdRules DNS List | 176,077 | 🟧 79.9% | 93.3% | 84.8% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Ultimate Blocklist | 106,445 | 🟩 5.8% | 6.5% | 37.1% |
| CHN: anti-AD | CHN: AdRules DNS List | 87,434 | 🟨 39.4% | 86.3% | 42.1% |
| CHN: AdRules DNS List | HaGeZi's Ultimate Blocklist | 86,477 | 🟨 21.2% | 41.6% | 30.2% |
| AdGuard DNS filter | HaGeZi's Ultimate Blocklist | 80,442 | 🟨 20.4% | 42.6% | 28.1% |
| AdGuard DNS filter | CHN: anti-AD | 78,018 | 🟨 36.8% | 41.3% | 77.0% |
| Phishing Army | HaGeZi's Threat Intelligence Feeds | 72,554 | 🟩 4.3% | 59.2% | 4.4% |
| CHN: anti-AD | HaGeZi's Ultimate Blocklist | 65,559 | 🟨 20.3% | 64.7% | 22.9% |
| CHN: AdRules DNS List | OISD Blocklist Small | 56,546 | 🟨 26.7% | 27.2% | 93.7% |
| HaGeZi's Ultimate Blocklist | OISD Blocklist Small | 56,518 | 🟩 19.5% | 19.7% | 93.7% |
| AdGuard DNS filter | OISD Blocklist Small | 55,994 | 🟨 29.0% | 29.7% | 92.8% |
| CHN: anti-AD | OISD Blocklist Small | 42,009 | 🟨 35.1% | 41.4% | 69.6% |
| CHN: AdRules DNS List | HaGeZi's Threat Intelligence Feeds | 33,418 | 🟩 1.8% | 16.1% | 2.0% |
| AdGuard DNS filter | HaGeZi's Threat Intelligence Feeds | 31,048 | 🟩 1.7% | 16.5% | 1.9% |
| HaGeZi's Threat Intelligence Feeds | OISD Blocklist Small | 24,365 | 🟩 1.4% | 1.5% | 40.4% |
| CHN: anti-AD | HaGeZi's Threat Intelligence Feeds | 23,137 | 🟩 1.3% | 22.8% | 1.4% |
| Phishing Army | HaGeZi's Ultimate Blocklist | 14,003 | 🟩 3.5% | 11.4% | 4.9% |
| Phishing Army | Phishing URL Blocklist (PhishTank and OpenPhish) | 12,784 | 🟩 10.2% | 10.4% | 82.7% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | HaGeZi's Threat Intelligence Feeds | 8,712 | 🟩 0.5% | 56.3% | 0.5% |

## 六、各源自去重率

> 输出覆盖 = 去重/聚合后该源仍覆盖的规则数（含正则规则）；自去重率 = 1 - 输出覆盖/原始。

| 源 | 原始规则 | 去重后有效 | 自去重率 |
|------|---------|-----------|---------|
| HaGeZi's Threat Intelligence Feeds | 1,650,046 | 1,647,193 | 0.2% |
| HaGeZi's Gambling Blocklist | 703,816 | 703,430 | 0.1% |
| HaGeZi's Ultimate Blocklist | 289,814 | 286,596 | 1.1% |
| CHN: AdRules DNS List | 212,117 | 207,747 | 2.1% |
| AdGuard DNS filter | 191,504 | 188,728 | 1.4% |
| Phishing Army | 146,193 | 122,541 | 16.2% |
| CHN: anti-AD | 102,112 | 101,372 | 0.7% |
| OISD Blocklist Small | 62,171 | 60,345 | 2.9% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 16,606 | 15,462 | 6.9% |
| Malicious URL Blocklist (URLHaus) | 2,117 | 1,991 | 6.0% |
| ShadowWhisperer's Dating List | 1,438 | 1,438 | 0.0% |
| Scam Blocklist by DurableNapkin | 909 | 905 | 0.4% |
| AWAvenue Ads Rule | 918 | 747 | 18.6% |
| Stalkerware Indicators List | 929 | 495 | 46.7% |
| HaGeZi's Windows/Office Tracker Blocklist | 395 | 387 | 2.0% |
| NoCoin Filter List | 312 | 269 | 13.8% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 0.0% |

## 七、冲突分析（白名单覆盖拦截）

> 被白名单移除的拦截规则；展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域。

| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |
|------|---------|---------|-----------|-----------|------|
| `ad.10010.com` | `||ad.10010.com^` | AWAvenue Ads Rule, OISD Blocklist Small, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||ad.10010.com^` | AdGuard DNS filter | 精确 |
| `ad.ourgame.com` | `||ad.ourgame.com^` | CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||ad.ourgame.com^` | AdGuard DNS filter | 精确 |
| `app.adjust.com` | `||app.adjust.com^` | AdGuard DNS filter | `@@||app.adjust.com^` | CHN: anti-AD | 精确 |
| `autocomplete.clearbit.com` | `||autocomplete.clearbit.com^` | HaGeZi's Ultimate Blocklist | `@@||autocomplete.clearbit.com^` | CHN: anti-AD | 精确 |
| `settings-win.data.microsoft.com` | `||settings-win.data.microsoft.com^` | HaGeZi's Ultimate Blocklist | `@@||settings-win.data.microsoft.com^` | CHN: anti-AD | 精确 |
| `ads.privacy.qq.com` | `||ads.privacy.qq.com^` | HaGeZi's Ultimate Blocklist | `@@||ads.privacy.qq.com^` | CHN: anti-AD | 精确 |

## 八、$ 修饰符分布

> 保留 `$` 修饰符（important / badfilter 等），这些列表是 AdGuard Home 语法适配的，修饰符有 DNS 层语义。

| 修饰符 | 规则数 | 占比 |
|--------|--------|------|
| `$important` | 5 | 100.0% |

## 九、白名单威胁情报审计

> 多层防御体系：本地 DNS/DoH、离线启发式、同形字检测 + 免费威胁情报（URLhaus/ThreatFox/RDAP/诈骗检测/DNSBL）+ 可选在线情报（VirusTotal/AI/GSB/PhishTank/urlscan/CT）。🔴 恶意建议移除此白名单；🟡 可疑需人工确认；🟢 安全可放心放行。需在配置中启用 `whitelist_audit.enabled`。

- 🔴 恶意：0
- 🟡 可疑：16
- 🟢 安全：86
- ⚪ 未知：1

### 防御层概览

| 层级 | 检测内容 | 状态 | 成本 | 命中数 |
|------|---------|------|------|--------|
| DNS 解析 | NXDOMAIN/私有IP检测 | ✅ 启用 | 免费 | 0 |
| DoH 加密解析 | NextDNS 加密传输，失败回退系统DNS | ✅ 启用 | 免费 | — |
| URLhaus | 恶意软件分发域名 | ✅ 启用 | 免费 | 0 |
| ThreatFox | C2 命令控制域名 | ✅ 启用 | 免费 | 0 |
| RDAP 域名年龄 | 新注册<30天标记 | ✅ 启用 | 免费 | 0 |
| MarketNow 诈骗检测 | 拼写劫持/可疑TLD/未注册 | ✅ 启用 | 免费 | 0 |
| DNSBL 黑名单 | Spamhaus DBL + SURBL | ✅ 启用 | 免费 | 0 |
| VirusTotal | 多引擎厂商信誉 | ⬜ 未启用 | 需API Key | - |
| AI/LLM 分类 | 低置信语义分类 | ⬜ 未启用 | 需API Key | - |
| 内置离线启发式 | 滥用TLD/连字符等（常驻，无开关键） | ✅ 启用 | 免费 | 0 |
| 同形字/拼写劫持 | Cyrillic/Greek 折叠+编辑距离 | ✅ 启用 | 免费·默认开 | 0 |
| MX/SPF 缺失线索 | 需 DNS，默认关 | ⬜ 未启用 | 可选 | - |
| Google Safe Browsing | 在线情报 | ⬜ 未启用 | 需API Key | - |
| PhishTank | 钓鱼库 | ⬜ 未启用 | 需API Key | - |
| urlscan 沙箱 | 可疑页面扫描 | ⬜ 未启用 | 需API Key(可选) | - |
| 证书透明度 CT | 接口预留，默认关 | ⬜ 未启用 | 可选 | — |

### 白名单域名类别分布

| 类别 | 数量 | 占比 |
|------|------|------|
| 广告/营销 | 3 | 2.9% |
| 分析/追踪 | 3 | 2.9% |
| CDN/基础设施 | 1 | 1.0% |
| 微软/Windows 遥测 | 10 | 9.7% |
| 社交/分享 | 3 | 2.9% |
| 电商/支付 | 3 | 2.9% |
| 隐私/安全 | 7 | 6.8% |
| 其他 | 73 | 70.9% |

### 分类置信度分布

> 高置信度=注册域名精确匹配(PSL)，可直接信任；中置信度=子域名前缀匹配，建议人工确认；低置信度=无法分类，需外部API或人工判断。

| 置信度等级 | 数量 | 占比 |
|-----------|------|------|
| 高置信度 (注册域名匹配) | 26 | 25.2% |
| 中置信度 (子域名前缀) | 4 | 3.9% |
| 低置信度 (无法分类) | 73 | 70.9% |

| 域名 | 评级 | 类别 | 置信度 | 原因 | 来源 |
|------|------|------|--------|------|------|
| `ad.cityu.edu.hk` | 🟡 可疑 | 其他 | 0.00 | 解析到私有/回环 IP: ['172.26.255.12', '172.26.255.11', '172.26.255.1', '172.26.255.2'] | CHN: anti-AD |
| `avqs.mcafee.com` | 🟡 可疑 | 隐私/安全 | 0.90 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `avts.mcafee.com` | 🟡 可疑 | 隐私/安全 | 0.90 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `counter-strike.net` | 🟡 可疑 | 其他 | 0.00 | 拼写劫持仿冒品牌 stripe（编辑距离 1） | CHN: anti-AD |
| `dishy.starlink.com` | 🟡 可疑 | 其他 | 0.00 | 解析到私有/回环 IP: ['192.168.100.1'] | HaGeZi's DNS Rebind Protection |
| `edge-enterprise.activity.windows.com` | 🟡 可疑 | 微软/Windows 遥测 | 0.90 | 解析到私有/回环 IP: ['127.0.0.1'] | CHN: anti-AD |
| `edge.activity.windows.com` | 🟡 可疑 | 微软/Windows 遥测 | 0.90 | 解析到私有/回环 IP: ['127.0.0.1'] | CHN: anti-AD |
| `fritz.nas` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `fritz.powerline` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `fritz.repeater` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `fritz.smartgateway` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `mail.abusix.zone` | 🟡 可疑 | 其他 | 0.00 | 拼写劫持仿冒品牌 gmail（编辑距离 1） | HaGeZi's DNS Rebind Protection |
| `meizu.coapi.moji.com` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | CHN: anti-AD |
| `plex.direct` | 🟡 可疑 | 其他 | 0.00 | 解析到私有/回环 IP: ['0.0.0.0'] | HaGeZi's DNS Rebind Protection |
| `router.asus.com` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `speedport.ip` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `tplinklogin.net` | ⚪ 未知 | 其他 | 0.00 | DNS 查询失败 (timeout)，但威胁情报无命中 | HaGeZi's DNS Rebind Protection |
| `3gppnetwork.org` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `ad-block.dns.adguard.com` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad-gone.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad-putting.gw.zt-express.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad.10010.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad.abchina.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad.azure.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad.kazakinfo.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad.ourgame.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad.siemens.com.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `adcdn.pingan.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ads.finance` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ads.privacy.qq.com` | 🟢 安全 | 社交/分享 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ads.taboola.com` | 🟢 安全 | 广告/营销 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `advert.kf5.com` | 🟢 安全 | 广告/营销 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `advertisement.taobao.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `analysis.chess.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `analysis.windows.net` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `api.ads.tvb.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `api.huangye.miui.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `app-advertise.zhihuishu.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `app.adjust.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `app.powerbi.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `asusrouter.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `autocomplete.clearbit.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `b.barracudacentral.org` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `backscatterer.org` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `baozhang.baidu.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `bl.blocklist.de` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `bl.spamcop.net` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `buyad.bi-xenon.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `captcha.su.baidu.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `center-h5api.m.taobao.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `chart-embed.service.newrelic.com` | 🟢 安全 | 分析/追踪 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `direct.quickconnect.to` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dns.msftncsi.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dnsbl.dronebl.org` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dnswl.org` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dq.spamhaus.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dxcloud.episerver.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `fritz.box` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `ftp.bmp.ovh` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `future.biz.weibo.com` | 🟢 安全 | 社交/分享 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `hash.cymru.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `hostkarma.junkemailfilter.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `img.ads.tvb.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `insideruser.microsoft.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ipv4only.arpa` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `log.mmstat.com` | 🟢 安全 | CDN/基础设施 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `mailspike.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `msftconnecttest.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `myunraid.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `news-app.abumedia.yql.yahoo.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `nordspam.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `passport.bobo.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `psbl.surriel.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `routerlogin.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `routerlogin.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `s.mvconf.f.360.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `sdkapi.sms.mob.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `settings-win.data.microsoft.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `skyapi.onedrive.live.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `skydrivesync.policies.live.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `sophosxl.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `spameatingmonkey.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `spamhaus.org` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `spamrats.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `stat.jseea.cn` | 🟢 安全 | 分析/追踪 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `stats.gov.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `stats.uptimerobot.com` | 🟢 安全 | 分析/追踪 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `storage.live.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `surbl.org` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tj.gov.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tongji.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tongji.edu.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tor.dan.me.uk` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `torexit.dan.me.uk` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkap.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkrepeater.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkwifi.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tracker.eu.org` | 🟢 安全 | 广告/营销 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tube.e.kuaishou.com` | 🟢 安全 | 社交/分享 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `uceprotect.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `uland.taobao.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `uribl.com` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `widget.intercom.io` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |

## 十、规则语法支持度

| 规则类型 | 语法示例 | 状态 | 处理方式 | 数量 |
|---------|---------|------|---------|------|
| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | 2,536,828 |
| 通配符 | `||*.example.com^` | ✅ 支持 | 聚合覆盖子域 | 0 |
| Allow 白名单 | `@@||example.com^` | ✅ 支持 | 分离到 whitelist.txt | 104 |
| 正则 | `/ads.*/` | ✅ 保留 | 原样保留 | 61 |
| IP 规则 | `||8.8.8.8^` | ✅ 支持 | 按域名字符串处理 | 74 |
| Hosts | `0.0.0.0 example.com` | ✅ 支持 | 转换为 `||domain^` | - |
| $ 修饰符 | `||x.com^$important` | ✅ 保留 | 保留修饰符，纳入去重键，跳过聚合，$important 抗白名单 | 5 |
| CSS/JS | `##.ad` | ❌ 丢弃 | DNS 层不支持 | 0 |

## 十一、域名后缀 Top 20

| 后缀 | 规则数 |
|------|--------|
| duckdns.org | 25,308 |
| fbcdn.net | 9,212 |
| whatsapp.net | 5,606 |
| gitbook.io | 3,940 |
| cloudfront.net | 2,633 |
| hl.cn | 2,433 |
| vercel.app | 2,362 |
| web.app | 2,142 |
| wixstudio.com | 2,068 |
| ddns.net | 2,065 |
| weebly.com | 2,043 |
| pages.dev | 2,015 |
| firebaseapp.com | 1,978 |
| amazonaws.com | 1,502 |
| run.app | 1,315 |
| godaddysites.com | 1,188 |
| netlify.app | 1,185 |
| r2.dev | 1,122 |
| co.com | 1,051 |
| my.id | 855 |

## 十二、性能与诊断

| 指标 | 数值 |
|------|------|
| 总耗时 | — |
| 源成功率 | 17/17 |
| 缓存命中 | — |
| 精确去重 | 795,878 |
| 规范化去重 | 3,212 |
| 正则去重 | 0 |
| 质量过滤丢弃 | 37 |
| 模式丢弃 | 1,038 |
| CSS 丢弃 | 0 |
| 本次新增域名 | 0 |
| 本次移除域名 | 0 |
| 平均域名长度 | 17.6 字符 |
| 最短/最长域名 | 2 / 236 字符 |

---
*AdGuard Rules Merger V7 · 自动生成 · 内容版本 2106c73078b3*
