# AdGuard Rules Merger V7 — 规则分析报告

> 内容版本 b57c29e9c8fa | 源：17/17

## 一、概览

| 指标 | 数值 |
|------|------|
| Block 规则 | 2,724,875 |
| Allow 白名单 | 104 |
| 综合去重率 | 26.2% |
| 聚合精简 | 39,565 |
| 冲突消解 | 6 |
| 带 $ 修饰符规则 | 5 |
| 总耗时 | — |

## 二、优化流水线

| 阶段 | 规则数 | 本阶段减少 |
|------|--------|-----------|
| 原始规则（Raw） | 3,689,964 | - |
| 去重后（精确 921,683 / 规范化 3,725 / 正则 0） | 2,764,556 | -925,408 |
| 聚合后（精确 39,563 / 通配符 2 / 升级 0） | 2,724,991 | -39,565 |
| 冲突消解后 | 2,724,979 | -6 |

## 三、规则类型与类别分布

### 规则类型

| 类型 | 数量 |
|------|------|
| domain | 2,724,844 |
| ip | 74 |
| regex | 61 |

### 类别分布（Block）

| 类别 | 数量 |
|------|------|
| malware | 1,979,963 |
| other | 368,002 |
| ads | 317,309 |
| phishing | 59,063 |
| tracking | 387 |
| mining | 151 |

## 四、按源贡献分析（独占 vs 共享）

> 统计覆盖最终输出规则（含正则规则）。输出覆盖 = 该源参与的最终规则数（独占+共享）；覆盖率 = 输出覆盖/原始规则；独占率 = 独占/输出覆盖。

| 源 | 原始规则 | 输出覆盖 | 覆盖率 | 独占规则 | 与他源共享 | 独占率 |
|------|---------|---------|--------|---------|-----------|--------|
| HaGeZi's Threat Intelligence Feeds | 1,980,867 | 1,978,840 | 99.9% | 1,507,065 | 471,775 | 76.2% |
| HaGeZi's Gambling Blocklist | 666,527 | 666,393 | 100.0% | 366,671 | 299,722 | 55.0% |
| HaGeZi's Ultimate Blocklist | 307,625 | 304,725 | 99.1% | 117,001 | 187,724 | 38.4% |
| Phishing Army | 145,416 | 122,606 | 84.3% | 45,731 | 76,875 | 37.3% |
| CHN: AdRules DNS List | 210,908 | 206,799 | 98.1% | 9,167 | 197,632 | 4.4% |
| CHN: anti-AD | 101,203 | 100,494 | 99.3% | 7,379 | 93,115 | 7.3% |
| AdGuard DNS filter | 190,381 | 187,853 | 98.7% | 4,874 | 182,979 | 2.6% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 17,278 | 16,221 | 93.9% | 2,244 | 13,977 | 13.8% |
| ShadowWhisperer's Dating List | 1,438 | 1,438 | 100.0% | 1,332 | 106 | 92.6% |
| Malicious URL Blocklist (URLHaus) | 2,071 | 1,968 | 95.0% | 580 | 1,388 | 29.5% |
| Stalkerware Indicators List | 929 | 504 | 54.3% | 257 | 247 | 51.0% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 100.0% | 57 | 0 | 100.0% |
| OISD Blocklist Small | 62,715 | 61,053 | 97.3% | 28 | 61,025 | 0.0% |
| Scam Blocklist by DurableNapkin | 921 | 918 | 99.7% | 4 | 914 | 0.4% |
| HaGeZi's Windows/Office Tracker Blocklist | 398 | 390 | 98.0% | 3 | 387 | 0.8% |
| NoCoin Filter List | 312 | 269 | 86.2% | 3 | 266 | 1.1% |
| AWAvenue Ads Rule | 918 | 748 | 81.5% | 0 | 748 | 0.0% |

## 五、源间重复矩阵（两两重复规则数 + 重复率）

> 每格 `共同规则数 (重复率%)`，重复率 = Jaccard = 共同/并集（对称）；对角线为该源输出覆盖数。颜色：🟥≥80% 🟧50–80% 🟨20–50% 🟩<20%（含 0）

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **1** | **1,978,840** | 🟩 298,593 (12.7%) | 🟩 118,014 (5.4%) | 🟩 28,213 (1.3%) | 🟩 26,041 (1.2%) | 🟩 66,021 (3.2%) | 🟩 21,780 (1.1%) | 🟩 21,796 (1.1%) | 🟩 3,582 (0.2%) | 🟩 1,146 (0.1%) | 🟩 28 (0.0%) | 🟩 829 (0.0%) | 🟩 18 (0.0%) | 🟩 214 (0.0%) | 🟩 3 (0.0%) | 🟩 117 (0.0%) | · |
| **2** | 🟩 298,593 (12.7%) | **666,393** | 🟩 1,656 (0.2%) | 🟩 466 (0.1%) | 🟩 422 (0.0%) | 🟩 151 (0.0%) | 🟩 219 (0.0%) | 🟩 144 (0.0%) | 🟩 24 (0.0%) | 🟩 3 (0.0%) | · | 🟩 3 (0.0%) | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · |
| **3** | 🟩 118,014 (5.4%) | 🟩 1,656 (0.2%) | **304,725** | 🟨 85,346 (20.0%) | 🟩 79,201 (19.2%) | 🟩 13,480 (3.3%) | 🟩 64,902 (19.1%) | 🟩 56,708 (18.3%) | 🟩 2,095 (0.7%) | 🟩 1,161 (0.4%) | 🟩 85 (0.0%) | 🟩 365 (0.1%) | 🟩 728 (0.2%) | 🟩 77 (0.0%) | 🟩 385 (0.1%) | 🟩 139 (0.0%) | · |
| **4** | 🟩 28,213 (1.3%) | 🟩 466 (0.1%) | 🟨 85,346 (20.0%) | **206,799** | 🟧 175,105 (79.8%) | 🟩 38 (0.0%) | 🟨 86,868 (39.4%) | 🟨 57,369 (27.3%) | 🟩 27 (0.0%) | 🟩 8 (0.0%) | 🟩 37 (0.0%) | 🟩 914 (0.4%) | 🟩 556 (0.3%) | 🟩 3 (0.0%) | 🟩 116 (0.1%) | 🟩 80 (0.0%) | · |
| **5** | 🟩 26,041 (1.2%) | 🟩 422 (0.0%) | 🟩 79,201 (19.2%) | 🟧 175,105 (79.8%) | **187,853** | 🟩 20 (0.0%) | 🟨 77,439 (36.7%) | 🟨 56,848 (29.6%) | 🟩 22 (0.0%) | 🟩 3 (0.0%) | 🟩 32 (0.0%) | 🟩 23 (0.0%) | 🟩 246 (0.1%) | 🟩 2 (0.0%) | 🟩 26 (0.0%) | 🟩 43 (0.0%) | · |
| **6** | 🟩 66,021 (3.2%) | 🟩 151 (0.0%) | 🟩 13,480 (3.3%) | 🟩 38 (0.0%) | 🟩 20 (0.0%) | **122,606** | 🟩 8 (0.0%) | 🟩 8 (0.0%) | 🟩 13,186 (10.5%) | 🟩 8 (0.0%) | · | 🟩 4 (0.0%) | · | · | · | · | · |
| **7** | 🟩 21,780 (1.1%) | 🟩 219 (0.0%) | 🟩 64,902 (19.1%) | 🟨 86,868 (39.4%) | 🟨 77,439 (36.7%) | 🟩 8 (0.0%) | **100,494** | 🟨 42,668 (35.9%) | 🟩 22 (0.0%) | 🟩 503 (0.5%) | 🟩 25 (0.0%) | 🟩 9 (0.0%) | 🟩 714 (0.7%) | 🟩 5 (0.0%) | 🟩 68 (0.1%) | 🟩 258 (0.3%) | · |
| **8** | 🟩 21,796 (1.1%) | 🟩 144 (0.0%) | 🟩 56,708 (18.3%) | 🟨 57,369 (27.3%) | 🟨 56,848 (29.6%) | 🟩 8 (0.0%) | 🟨 42,668 (35.9%) | **61,053** | 🟩 10 (0.0%) | 🟩 5 (0.0%) | 🟩 23 (0.0%) | 🟩 13 (0.0%) | 🟩 696 (1.1%) | 🟩 1 (0.0%) | 🟩 26 (0.0%) | 🟩 52 (0.1%) | · |
| **9** | 🟩 3,582 (0.2%) | 🟩 24 (0.0%) | 🟩 2,095 (0.7%) | 🟩 27 (0.0%) | 🟩 22 (0.0%) | 🟩 13,186 (10.5%) | 🟩 22 (0.0%) | 🟩 10 (0.0%) | **16,221** | 🟩 10 (0.1%) | · | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 2 (0.0%) | · |
| **10** | 🟩 1,146 (0.1%) | 🟩 3 (0.0%) | 🟩 1,161 (0.4%) | 🟩 8 (0.0%) | 🟩 3 (0.0%) | 🟩 8 (0.0%) | 🟩 503 (0.5%) | 🟩 5 (0.0%) | 🟩 10 (0.1%) | **1,968** | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | · | · |
| **11** | 🟩 28 (0.0%) | · | 🟩 85 (0.0%) | 🟩 37 (0.0%) | 🟩 32 (0.0%) | · | 🟩 25 (0.0%) | 🟩 23 (0.0%) | · | · | **1,438** | 🟩 2 (0.1%) | · | · | · | · | · |
| **12** | 🟩 829 (0.0%) | 🟩 3 (0.0%) | 🟩 365 (0.1%) | 🟩 914 (0.4%) | 🟩 23 (0.0%) | 🟩 4 (0.0%) | 🟩 9 (0.0%) | 🟩 13 (0.0%) | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 2 (0.1%) | **918** | · | · | · | 🟩 1 (0.1%) | · |
| **13** | 🟩 18 (0.0%) | · | 🟩 728 (0.2%) | 🟩 556 (0.3%) | 🟩 246 (0.1%) | · | 🟩 714 (0.7%) | 🟩 696 (1.1%) | 🟩 1 (0.0%) | · | · | · | **748** | 🟩 1 (0.1%) | 🟩 6 (0.5%) | · | · |
| **14** | 🟩 214 (0.0%) | 🟩 1 (0.0%) | 🟩 77 (0.0%) | 🟩 3 (0.0%) | 🟩 2 (0.0%) | · | 🟩 5 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | · | 🟩 1 (0.1%) | **504** | · | · | · |
| **15** | 🟩 3 (0.0%) | · | 🟩 385 (0.1%) | 🟩 116 (0.1%) | 🟩 26 (0.0%) | · | 🟩 68 (0.1%) | 🟩 26 (0.0%) | · | · | · | · | 🟩 6 (0.5%) | · | **390** | · | · |
| **16** | 🟩 117 (0.0%) | 🟩 1 (0.0%) | 🟩 139 (0.0%) | 🟩 80 (0.0%) | 🟩 43 (0.0%) | · | 🟩 258 (0.3%) | 🟩 52 (0.1%) | 🟩 2 (0.0%) | · | · | 🟩 1 (0.1%) | · | · | · | **269** | · |
| **17** | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | **57** |

**源编号对照**（按输出覆盖降序）

| # | 源 | 输出覆盖 |
|---|---|----------|
| 1 | HaGeZi's Threat Intelligence Feeds | 1,978,840 |
| 2 | HaGeZi's Gambling Blocklist | 666,393 |
| 3 | HaGeZi's Ultimate Blocklist | 304,725 |
| 4 | CHN: AdRules DNS List | 206,799 |
| 5 | AdGuard DNS filter | 187,853 |
| 6 | Phishing Army | 122,606 |
| 7 | CHN: anti-AD | 100,494 |
| 8 | OISD Blocklist Small | 61,053 |
| 9 | Phishing URL Blocklist (PhishTank and OpenPhish) | 16,221 |
| 10 | Malicious URL Blocklist (URLHaus) | 1,968 |
| 11 | ShadowWhisperer's Dating List | 1,438 |
| 12 | Scam Blocklist by DurableNapkin | 918 |
| 13 | AWAvenue Ads Rule | 748 |
| 14 | Stalkerware Indicators List | 504 |
| 15 | HaGeZi's Windows/Office Tracker Blocklist | 390 |
| 16 | NoCoin Filter List | 269 |
| 17 | HaGeZi's DNS Rebind Protection | 57 |

### 源间重复 Top 20（双向覆盖率明细）

> 每对源共同拥有的规则数；覆盖率 = 共同规则数 / 该源输出覆盖数。

| 源 A | 源 B | 共同规则数 | 重复率 | A 覆盖率 | B 覆盖率 |
|------|------|-----------|--------|---------|---------|
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Gambling Blocklist | 298,593 | 🟩 12.7% | 15.1% | 44.8% |
| AdGuard DNS filter | CHN: AdRules DNS List | 175,105 | 🟧 79.8% | 93.2% | 84.7% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Ultimate Blocklist | 118,014 | 🟩 5.4% | 6.0% | 38.7% |
| CHN: anti-AD | CHN: AdRules DNS List | 86,868 | 🟨 39.4% | 86.4% | 42.0% |
| CHN: AdRules DNS List | HaGeZi's Ultimate Blocklist | 85,346 | 🟨 20.0% | 41.3% | 28.0% |
| AdGuard DNS filter | HaGeZi's Ultimate Blocklist | 79,201 | 🟩 19.2% | 42.2% | 26.0% |
| AdGuard DNS filter | CHN: anti-AD | 77,439 | 🟨 36.7% | 41.2% | 77.1% |
| Phishing Army | HaGeZi's Threat Intelligence Feeds | 66,021 | 🟩 3.2% | 53.8% | 3.3% |
| CHN: anti-AD | HaGeZi's Ultimate Blocklist | 64,902 | 🟩 19.1% | 64.6% | 21.3% |
| CHN: AdRules DNS List | OISD Blocklist Small | 57,369 | 🟨 27.3% | 27.7% | 94.0% |
| AdGuard DNS filter | OISD Blocklist Small | 56,848 | 🟨 29.6% | 30.3% | 93.1% |
| HaGeZi's Ultimate Blocklist | OISD Blocklist Small | 56,708 | 🟩 18.3% | 18.6% | 92.9% |
| CHN: anti-AD | OISD Blocklist Small | 42,668 | 🟨 35.9% | 42.5% | 69.9% |
| CHN: AdRules DNS List | HaGeZi's Threat Intelligence Feeds | 28,213 | 🟩 1.3% | 13.6% | 1.4% |
| AdGuard DNS filter | HaGeZi's Threat Intelligence Feeds | 26,041 | 🟩 1.2% | 13.9% | 1.3% |
| HaGeZi's Threat Intelligence Feeds | OISD Blocklist Small | 21,796 | 🟩 1.1% | 1.1% | 35.7% |
| CHN: anti-AD | HaGeZi's Threat Intelligence Feeds | 21,780 | 🟩 1.1% | 21.7% | 1.1% |
| Phishing Army | HaGeZi's Ultimate Blocklist | 13,480 | 🟩 3.3% | 11.0% | 4.4% |
| Phishing Army | Phishing URL Blocklist (PhishTank and OpenPhish) | 13,186 | 🟩 10.5% | 10.8% | 81.3% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | HaGeZi's Threat Intelligence Feeds | 3,582 | 🟩 0.2% | 22.1% | 0.2% |

## 六、各源自去重率

> 输出覆盖 = 去重/聚合后该源仍覆盖的规则数（含正则规则）；自去重率 = 1 - 输出覆盖/原始。

| 源 | 原始规则 | 去重后有效 | 自去重率 |
|------|---------|-----------|---------|
| HaGeZi's Threat Intelligence Feeds | 1,980,867 | 1,978,840 | 0.1% |
| HaGeZi's Gambling Blocklist | 666,527 | 666,393 | 0.0% |
| HaGeZi's Ultimate Blocklist | 307,625 | 304,725 | 0.9% |
| CHN: AdRules DNS List | 210,908 | 206,799 | 1.9% |
| AdGuard DNS filter | 190,381 | 187,853 | 1.3% |
| Phishing Army | 145,416 | 122,606 | 15.7% |
| CHN: anti-AD | 101,203 | 100,494 | 0.7% |
| OISD Blocklist Small | 62,715 | 61,053 | 2.7% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 17,278 | 16,221 | 6.1% |
| Malicious URL Blocklist (URLHaus) | 2,071 | 1,968 | 5.0% |
| ShadowWhisperer's Dating List | 1,438 | 1,438 | 0.0% |
| Scam Blocklist by DurableNapkin | 921 | 918 | 0.3% |
| AWAvenue Ads Rule | 918 | 748 | 18.5% |
| Stalkerware Indicators List | 929 | 504 | 45.7% |
| HaGeZi's Windows/Office Tracker Blocklist | 398 | 390 | 2.0% |
| NoCoin Filter List | 312 | 269 | 13.8% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 0.0% |

## 七、冲突分析（白名单覆盖拦截）

> 被白名单移除的拦截规则；展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域。

| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |
|------|---------|---------|-----------|-----------|------|
| `app.adjust.com` | `||app.adjust.com^` | AdGuard DNS filter | `@@||app.adjust.com^` | CHN: anti-AD | 精确 |
| `autocomplete.clearbit.com` | `||autocomplete.clearbit.com^` | HaGeZi's Ultimate Blocklist | `@@||autocomplete.clearbit.com^` | CHN: anti-AD | 精确 |
| `settings-win.data.microsoft.com` | `||settings-win.data.microsoft.com^` | HaGeZi's Ultimate Blocklist | `@@||settings-win.data.microsoft.com^` | CHN: anti-AD | 精确 |
| `ad.ourgame.com` | `||ad.ourgame.com^` | HaGeZi's Ultimate Blocklist, CHN: AdRules DNS List | `@@||ad.ourgame.com^` | AdGuard DNS filter | 精确 |
| `ads.privacy.qq.com` | `||ads.privacy.qq.com^` | HaGeZi's Ultimate Blocklist | `@@||ads.privacy.qq.com^` | CHN: anti-AD | 精确 |
| `ad.10010.com` | `||ad.10010.com^` | AWAvenue Ads Rule, OISD Blocklist Small, CHN: anti-AD, HaGeZi's Ultimate Blocklist, CHN: AdRules DNS List | `@@||ad.10010.com^` | AdGuard DNS filter | 精确 |

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
| `ad.cityu.edu.hk` | 🟡 可疑 | 其他 | 0.00 | 解析到私有/回环 IP: ['172.26.255.2', '172.26.255.12', '172.26.255.11', '172.26.255.1'] | CHN: anti-AD |
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
| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | 2,724,844 |
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
| eu.cc | 25,660 |
| fbcdn.net | 9,211 |
| whatsapp.net | 5,606 |
| cloudfront.net | 2,609 |
| hl.cn | 2,326 |
| pages.dev | 2,266 |
| wixstudio.com | 2,098 |
| web.app | 1,985 |
| firebaseapp.com | 1,909 |
| amazonaws.com | 1,465 |
| weebly.com | 1,323 |
| run.app | 1,259 |
| r2.dev | 1,181 |
| vercel.app | 1,083 |
| co.com | 825 |
| lovable.app | 707 |
| workers.dev | 571 |
| googleapis.com | 550 |
| connexus.net.au | 536 |
| ru.com | 516 |

## 十二、性能与诊断

| 指标 | 数值 |
|------|------|
| 总耗时 | — |
| 源成功率 | 17/17 |
| 缓存命中 | — |
| 精确去重 | 921,683 |
| 规范化去重 | 3,725 |
| 正则去重 | 0 |
| 质量过滤丢弃 | 37 |
| 模式丢弃 | 1,038 |
| CSS 丢弃 | 0 |
| 本次新增域名 | 0 |
| 本次移除域名 | 0 |
| 平均域名长度 | 17.4 字符 |
| 最短/最长域名 | 2 / 198 字符 |

---
*AdGuard Rules Merger V7 · 自动生成 · 内容版本 b57c29e9c8fa*
