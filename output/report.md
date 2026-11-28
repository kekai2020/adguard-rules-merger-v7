# AdGuard Rules Merger V7 — 规则分析报告

> 内容版本 bb8030323543 | 源：17/17

## 一、概览

| 指标 | 数值 |
|------|------|
| Block 规则 | 2,120,703 |
| Allow 白名单 | 121 |
| 综合去重率 | 25.9% |
| 聚合精简 | 68,784 |
| 冲突消解 | 10 |
| 带 $ 修饰符规则 | 5 |
| 总耗时 | — |

## 二、优化流水线

| 阶段 | 规则数 | 本阶段减少 |
|------|--------|-----------|
| 原始规则（Raw） | 2,863,727 | - |
| 去重后（精确 669,245 / 规范化 4,858 / 正则 0） | 2,189,624 | -674,103 |
| 聚合后（精确 68,782 / 通配符 2 / 升级 0） | 2,120,840 | -68,784 |
| 冲突消解后 | 2,120,824 | -10 |

## 三、规则类型与类别分布

### 规则类型

| 类型 | 数量 |
|------|------|
| domain | 2,120,689 |
| ip | 74 |
| regex | 61 |

### 类别分布（Block）

| 类别 | 数量 |
|------|------|
| malware | 1,085,938 |
| other | 627,482 |
| ads | 341,790 |
| phishing | 64,924 |
| tracking | 403 |
| mining | 166 |

## 四、按源贡献分析（独占 vs 共享）

> 统计覆盖最终输出规则（含正则规则）。输出覆盖 = 该源参与的最终规则数（独占+共享）；覆盖率 = 输出覆盖/原始规则；独占率 = 独占/输出覆盖。

| 源 | 原始规则 | 输出覆盖 | 覆盖率 | 独占规则 | 与他源共享 | 独占率 |
|------|---------|---------|--------|---------|-----------|--------|
| HaGeZi's Threat Intelligence Feeds | 1,116,347 | 1,084,678 | 97.2% | 870,730 | 213,948 | 80.3% |
| HaGeZi's Gambling Blocklist | 718,478 | 718,366 | 100.0% | 626,146 | 92,220 | 87.2% |
| HaGeZi's Ultimate Blocklist | 282,142 | 279,496 | 99.1% | 128,099 | 151,397 | 45.8% |
| Phishing Army | 146,583 | 123,491 | 84.2% | 52,740 | 70,751 | 42.7% |
| CHN: AdRules DNS List | 216,035 | 211,965 | 98.1% | 9,549 | 202,416 | 4.5% |
| CHN: anti-AD | 101,970 | 101,279 | 99.3% | 7,403 | 93,876 | 7.3% |
| AdGuard DNS filter | 195,147 | 192,556 | 98.7% | 4,896 | 187,660 | 2.5% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 16,192 | 15,302 | 94.5% | 2,209 | 13,093 | 14.4% |
| ShadowWhisperer's Dating List | 1,438 | 1,438 | 100.0% | 1,337 | 101 | 93.0% |
| Malicious URL Blocklist (URLHaus) | 2,242 | 2,225 | 99.2% | 812 | 1,413 | 36.5% |
| Stalkerware Indicators List | 929 | 503 | 54.1% | 202 | 301 | 40.2% |
| HaGeZi's DNS Rebind Protection | 74 | 74 | 100.0% | 74 | 0 | 100.0% |
| OISD Blocklist Small | 63,599 | 61,863 | 97.3% | 64 | 61,799 | 0.1% |
| Scam Blocklist by DurableNapkin | 910 | 906 | 99.6% | 4 | 902 | 0.4% |
| NoCoin Filter List | 312 | 269 | 86.2% | 3 | 266 | 1.1% |
| HaGeZi's Windows/Office Tracker Blocklist | 411 | 403 | 98.1% | 1 | 402 | 0.2% |
| AWAvenue Ads Rule | 918 | 748 | 81.5% | 0 | 748 | 0.0% |

## 五、源间重复矩阵（两两重复规则数 + 重复率）

> 每格 `共同规则数 (重复率%)`，重复率 = Jaccard = 共同/并集（对称）；对角线为该源输出覆盖数。颜色：🟥≥80% 🟧50–80% 🟨20–50% 🟩<20%（含 0）

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **1** | **1,084,678** | 🟩 90,825 (5.3%) | 🟩 73,286 (5.7%) | 🟩 20,913 (1.6%) | 🟩 19,278 (1.5%) | 🟩 60,995 (5.3%) | 🟩 17,931 (1.5%) | 🟩 19,382 (1.7%) | 🟩 3,647 (0.3%) | 🟩 1,191 (0.1%) | 🟩 18 (0.0%) | 🟩 833 (0.1%) | 🟩 13 (0.0%) | 🟩 288 (0.0%) | · | 🟩 102 (0.0%) | · |
| **2** | 🟩 90,825 (5.3%) | **718,366** | 🟩 2,391 (0.2%) | 🟩 503 (0.1%) | 🟩 464 (0.1%) | 🟩 131 (0.0%) | 🟩 239 (0.0%) | 🟩 165 (0.0%) | 🟩 25 (0.0%) | 🟩 6 (0.0%) | · | 🟩 4 (0.0%) | · | 🟩 2 (0.0%) | · | 🟩 2 (0.0%) | · |
| **3** | 🟩 73,286 (5.7%) | 🟩 2,391 (0.2%) | **279,496** | 🟨 86,035 (21.2%) | 🟨 80,092 (20.4%) | 🟩 13,438 (3.4%) | 🟨 64,699 (20.5%) | 🟩 56,669 (19.9%) | 🟩 1,779 (0.6%) | 🟩 734 (0.3%) | 🟩 86 (0.0%) | 🟩 374 (0.1%) | 🟩 728 (0.3%) | 🟩 75 (0.0%) | 🟩 400 (0.1%) | 🟩 137 (0.0%) | · |
| **4** | 🟩 20,913 (1.6%) | 🟩 503 (0.1%) | 🟨 86,035 (21.2%) | **211,965** | 🟥 179,800 (80.0%) | 🟩 40 (0.0%) | 🟨 87,635 (38.8%) | 🟨 58,193 (27.0%) | 🟩 28 (0.0%) | 🟩 6 (0.0%) | 🟩 37 (0.0%) | 🟩 902 (0.4%) | 🟩 555 (0.3%) | 🟩 3 (0.0%) | 🟩 117 (0.1%) | 🟩 80 (0.0%) | · |
| **5** | 🟩 19,278 (1.5%) | 🟩 464 (0.1%) | 🟨 80,092 (20.4%) | 🟥 179,800 (80.0%) | **192,556** | 🟩 20 (0.0%) | 🟨 78,078 (36.2%) | 🟨 57,695 (29.3%) | 🟩 24 (0.0%) | 🟩 3 (0.0%) | 🟩 32 (0.0%) | 🟩 23 (0.0%) | 🟩 247 (0.1%) | 🟩 2 (0.0%) | 🟩 26 (0.0%) | 🟩 42 (0.0%) | · |
| **6** | 🟩 60,995 (5.3%) | 🟩 131 (0.0%) | 🟩 13,438 (3.4%) | 🟩 40 (0.0%) | 🟩 20 (0.0%) | **123,491** | 🟩 8 (0.0%) | 🟩 8 (0.0%) | 🟩 12,346 (9.8%) | 🟩 7 (0.0%) | · | 🟩 5 (0.0%) | · | · | · | · | · |
| **7** | 🟩 17,931 (1.5%) | 🟩 239 (0.0%) | 🟨 64,699 (20.5%) | 🟨 87,635 (38.8%) | 🟨 78,078 (36.2%) | 🟩 8 (0.0%) | **101,279** | 🟨 43,050 (35.8%) | 🟩 23 (0.0%) | 🟩 514 (0.5%) | 🟩 25 (0.0%) | 🟩 9 (0.0%) | 🟩 714 (0.7%) | 🟩 5 (0.0%) | 🟩 69 (0.1%) | 🟩 258 (0.3%) | · |
| **8** | 🟩 19,382 (1.7%) | 🟩 165 (0.0%) | 🟩 56,669 (19.9%) | 🟨 58,193 (27.0%) | 🟨 57,695 (29.3%) | 🟩 8 (0.0%) | 🟨 43,050 (35.8%) | **61,863** | 🟩 11 (0.0%) | 🟩 4 (0.0%) | 🟩 23 (0.0%) | 🟩 13 (0.0%) | 🟩 695 (1.1%) | 🟩 1 (0.0%) | 🟩 26 (0.0%) | 🟩 49 (0.1%) | · |
| **9** | 🟩 3,647 (0.3%) | 🟩 25 (0.0%) | 🟩 1,779 (0.6%) | 🟩 28 (0.0%) | 🟩 24 (0.0%) | 🟩 12,346 (9.8%) | 🟩 23 (0.0%) | 🟩 11 (0.0%) | **15,302** | 🟩 8 (0.0%) | · | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 2 (0.0%) | · |
| **10** | 🟩 1,191 (0.1%) | 🟩 6 (0.0%) | 🟩 734 (0.3%) | 🟩 6 (0.0%) | 🟩 3 (0.0%) | 🟩 7 (0.0%) | 🟩 514 (0.5%) | 🟩 4 (0.0%) | 🟩 8 (0.0%) | **2,225** | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | · | · |
| **11** | 🟩 18 (0.0%) | · | 🟩 86 (0.0%) | 🟩 37 (0.0%) | 🟩 32 (0.0%) | · | 🟩 25 (0.0%) | 🟩 23 (0.0%) | · | · | **1,438** | 🟩 2 (0.1%) | · | · | · | · | · |
| **12** | 🟩 833 (0.1%) | 🟩 4 (0.0%) | 🟩 374 (0.1%) | 🟩 902 (0.4%) | 🟩 23 (0.0%) | 🟩 5 (0.0%) | 🟩 9 (0.0%) | 🟩 13 (0.0%) | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 2 (0.1%) | **906** | · | · | · | 🟩 1 (0.1%) | · |
| **13** | 🟩 13 (0.0%) | · | 🟩 728 (0.3%) | 🟩 555 (0.3%) | 🟩 247 (0.1%) | · | 🟩 714 (0.7%) | 🟩 695 (1.1%) | 🟩 1 (0.0%) | · | · | · | **748** | 🟩 1 (0.1%) | 🟩 6 (0.5%) | · | · |
| **14** | 🟩 288 (0.0%) | 🟩 2 (0.0%) | 🟩 75 (0.0%) | 🟩 3 (0.0%) | 🟩 2 (0.0%) | · | 🟩 5 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | · | 🟩 1 (0.1%) | **503** | · | · | · |
| **15** | · | · | 🟩 400 (0.1%) | 🟩 117 (0.1%) | 🟩 26 (0.0%) | · | 🟩 69 (0.1%) | 🟩 26 (0.0%) | · | · | · | · | 🟩 6 (0.5%) | · | **403** | · | · |
| **16** | 🟩 102 (0.0%) | 🟩 2 (0.0%) | 🟩 137 (0.0%) | 🟩 80 (0.0%) | 🟩 42 (0.0%) | · | 🟩 258 (0.3%) | 🟩 49 (0.1%) | 🟩 2 (0.0%) | · | · | 🟩 1 (0.1%) | · | · | · | **269** | · |
| **17** | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | **74** |

**源编号对照**（按输出覆盖降序）

| # | 源 | 输出覆盖 |
|---|---|----------|
| 1 | HaGeZi's Threat Intelligence Feeds | 1,084,678 |
| 2 | HaGeZi's Gambling Blocklist | 718,366 |
| 3 | HaGeZi's Ultimate Blocklist | 279,496 |
| 4 | CHN: AdRules DNS List | 211,965 |
| 5 | AdGuard DNS filter | 192,556 |
| 6 | Phishing Army | 123,491 |
| 7 | CHN: anti-AD | 101,279 |
| 8 | OISD Blocklist Small | 61,863 |
| 9 | Phishing URL Blocklist (PhishTank and OpenPhish) | 15,302 |
| 10 | Malicious URL Blocklist (URLHaus) | 2,225 |
| 11 | ShadowWhisperer's Dating List | 1,438 |
| 12 | Scam Blocklist by DurableNapkin | 906 |
| 13 | AWAvenue Ads Rule | 748 |
| 14 | Stalkerware Indicators List | 503 |
| 15 | HaGeZi's Windows/Office Tracker Blocklist | 403 |
| 16 | NoCoin Filter List | 269 |
| 17 | HaGeZi's DNS Rebind Protection | 74 |

### 源间重复 Top 20（双向覆盖率明细）

> 每对源共同拥有的规则数；覆盖率 = 共同规则数 / 该源输出覆盖数。

| 源 A | 源 B | 共同规则数 | 重复率 | A 覆盖率 | B 覆盖率 |
|------|------|-----------|--------|---------|---------|
| AdGuard DNS filter | CHN: AdRules DNS List | 179,800 | 🟥 80.0% | 93.4% | 84.8% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Gambling Blocklist | 90,825 | 🟩 5.3% | 8.4% | 12.6% |
| CHN: anti-AD | CHN: AdRules DNS List | 87,635 | 🟨 38.8% | 86.5% | 41.3% |
| CHN: AdRules DNS List | HaGeZi's Ultimate Blocklist | 86,035 | 🟨 21.2% | 40.6% | 30.8% |
| AdGuard DNS filter | HaGeZi's Ultimate Blocklist | 80,092 | 🟨 20.4% | 41.6% | 28.7% |
| AdGuard DNS filter | CHN: anti-AD | 78,078 | 🟨 36.2% | 40.5% | 77.1% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Ultimate Blocklist | 73,286 | 🟩 5.7% | 6.8% | 26.2% |
| CHN: anti-AD | HaGeZi's Ultimate Blocklist | 64,699 | 🟨 20.5% | 63.9% | 23.1% |
| Phishing Army | HaGeZi's Threat Intelligence Feeds | 60,995 | 🟩 5.3% | 49.4% | 5.6% |
| CHN: AdRules DNS List | OISD Blocklist Small | 58,193 | 🟨 27.0% | 27.5% | 94.1% |
| AdGuard DNS filter | OISD Blocklist Small | 57,695 | 🟨 29.3% | 30.0% | 93.3% |
| HaGeZi's Ultimate Blocklist | OISD Blocklist Small | 56,669 | 🟩 19.9% | 20.3% | 91.6% |
| CHN: anti-AD | OISD Blocklist Small | 43,050 | 🟨 35.8% | 42.5% | 69.6% |
| CHN: AdRules DNS List | HaGeZi's Threat Intelligence Feeds | 20,913 | 🟩 1.6% | 9.9% | 1.9% |
| HaGeZi's Threat Intelligence Feeds | OISD Blocklist Small | 19,382 | 🟩 1.7% | 1.8% | 31.3% |
| AdGuard DNS filter | HaGeZi's Threat Intelligence Feeds | 19,278 | 🟩 1.5% | 10.0% | 1.8% |
| CHN: anti-AD | HaGeZi's Threat Intelligence Feeds | 17,931 | 🟩 1.5% | 17.7% | 1.7% |
| Phishing Army | HaGeZi's Ultimate Blocklist | 13,438 | 🟩 3.4% | 10.9% | 4.8% |
| Phishing Army | Phishing URL Blocklist (PhishTank and OpenPhish) | 12,346 | 🟩 9.8% | 10.0% | 80.7% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | HaGeZi's Threat Intelligence Feeds | 3,647 | 🟩 0.3% | 23.8% | 0.3% |

## 六、各源自去重率

> 输出覆盖 = 去重/聚合后该源仍覆盖的规则数（含正则规则）；自去重率 = 1 - 输出覆盖/原始。

| 源 | 原始规则 | 去重后有效 | 自去重率 |
|------|---------|-----------|---------|
| HaGeZi's Threat Intelligence Feeds | 1,116,347 | 1,084,678 | 2.8% |
| HaGeZi's Gambling Blocklist | 718,478 | 718,366 | 0.0% |
| HaGeZi's Ultimate Blocklist | 282,142 | 279,496 | 0.9% |
| CHN: AdRules DNS List | 216,035 | 211,965 | 1.9% |
| AdGuard DNS filter | 195,147 | 192,556 | 1.3% |
| Phishing Army | 146,583 | 123,491 | 15.8% |
| CHN: anti-AD | 101,970 | 101,279 | 0.7% |
| OISD Blocklist Small | 63,599 | 61,863 | 2.7% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 16,192 | 15,302 | 5.5% |
| Malicious URL Blocklist (URLHaus) | 2,242 | 2,225 | 0.8% |
| ShadowWhisperer's Dating List | 1,438 | 1,438 | 0.0% |
| Scam Blocklist by DurableNapkin | 910 | 906 | 0.4% |
| AWAvenue Ads Rule | 918 | 748 | 18.5% |
| Stalkerware Indicators List | 929 | 503 | 45.9% |
| HaGeZi's Windows/Office Tracker Blocklist | 411 | 403 | 1.9% |
| NoCoin Filter List | 312 | 269 | 13.8% |
| HaGeZi's DNS Rebind Protection | 74 | 74 | 0.0% |

## 七、冲突分析（白名单覆盖拦截）

> 被白名单移除的拦截规则；展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域。

| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |
|------|---------|---------|-----------|-----------|------|
| `app.adjust.com` | `||app.adjust.com^` | AdGuard DNS filter | `@@||app.adjust.com^` | CHN: anti-AD | 精确 |
| `ad.10010.com` | `||ad.10010.com^` | AWAvenue Ads Rule, OISD Blocklist Small, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||ad.10010.com^` | AdGuard DNS filter | 精确 |
| `ad.ourgame.com` | `||ad.ourgame.com^` | CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||ad.ourgame.com^` | AdGuard DNS filter | 精确 |
| `wpad.www.tendawifi.com` | `||wpad.www.tendawifi.com^` | CHN: AdRules DNS List | `@@||tendawifi.com^` | HaGeZi's DNS Rebind Protection | 级联 |
| `autocomplete.clearbit.com` | `||autocomplete.clearbit.com^` | HaGeZi's Ultimate Blocklist | `@@||autocomplete.clearbit.com^` | CHN: anti-AD | 精确 |
| `ad.cityu.edu.hk` | `||ad.cityu.edu.hk^` | HaGeZi's Ultimate Blocklist | `@@||ad.cityu.edu.hk^` | CHN: anti-AD | 精确 |
| `settings-win.data.microsoft.com` | `||settings-win.data.microsoft.com^` | HaGeZi's Ultimate Blocklist | `@@||settings-win.data.microsoft.com^` | CHN: anti-AD | 精确 |
| `log.miwifi.com` | `||log.miwifi.com^` | HaGeZi's Ultimate Blocklist | `@@||miwifi.com^` | HaGeZi's DNS Rebind Protection | 级联 |
| `ads.privacy.qq.com` | `||ads.privacy.qq.com^` | HaGeZi's Ultimate Blocklist | `@@||ads.privacy.qq.com^` | CHN: anti-AD | 精确 |
| `mailspike.net` | `||mailspike.net^` | HaGeZi's Threat Intelligence Feeds | `@@||mailspike.net^` | HaGeZi's DNS Rebind Protection | 精确 |

## 八、$ 修饰符分布

> 保留 `$` 修饰符（important / badfilter 等），这些列表是 AdGuard Home 语法适配的，修饰符有 DNS 层语义。

| 修饰符 | 规则数 | 占比 |
|--------|--------|------|
| `$important` | 5 | 100.0% |

## 九、白名单威胁情报审计

> 多层防御体系：本地 DNS/DoH、离线启发式、同形字检测 + 免费威胁情报（URLhaus/ThreatFox/RDAP/诈骗检测/DNSBL）+ 可选在线情报（VirusTotal/AI/GSB/PhishTank/urlscan/CT）。🔴 恶意建议移除此白名单；🟡 可疑需人工确认；🟢 安全可放心放行。需在配置中启用 `whitelist_audit.enabled`。

- 🔴 恶意：0
- 🟡 可疑：17
- 🟢 安全：100
- ⚪ 未知：3

### 防御层概览

| 层级 | 检测内容 | 状态 | 成本 | 命中数 |
|------|---------|------|------|--------|
| DNS 解析 | NXDOMAIN/私有IP检测 | ✅ 启用 | 免费 | 15 |
| DoH 加密解析 | NextDNS 加密传输，失败回退系统DNS | ✅ 启用 | 免费 | — |
| URLhaus | 恶意软件分发域名 | ✅ 启用 | 免费 | 0 |
| ThreatFox | C2 命令控制域名 | ✅ 启用 | 免费 | 0 |
| RDAP 域名年龄 | 新注册<30天标记 | ✅ 启用 | 免费 | 0 |
| MarketNow 诈骗检测 | 拼写劫持/可疑TLD/未注册 | ✅ 启用 | 免费 | 0 |
| DNSBL 黑名单 | Spamhaus DBL + SURBL | ✅ 启用 | 免费 | 0 |
| VirusTotal | 多引擎厂商信誉 | ⬜ 未启用 | 需API Key | - |
| AI/LLM 分类 | 低置信语义分类 | ⬜ 未启用 | 需API Key | - |
| 内置离线启发式 | 滥用TLD/连字符等（常驻，无开关键） | ✅ 启用 | 免费 | 0 |
| 同形字/拼写劫持 | Cyrillic/Greek 折叠+编辑距离 | ✅ 启用 | 免费·默认开 | 2 |
| MX/SPF 缺失线索 | 需 DNS，默认关 | ⬜ 未启用 | 可选 | - |
| Google Safe Browsing | 在线情报 | ⬜ 未启用 | 需API Key | - |
| PhishTank | 钓鱼库 | ⬜ 未启用 | 需API Key | - |
| urlscan 沙箱 | 可疑页面扫描 | ⬜ 未启用 | 需API Key(可选) | - |
| 证书透明度 CT | 接口预留，默认关 | ⬜ 未启用 | 可选 | — |

### 白名单域名类别分布

| 类别 | 数量 | 占比 |
|------|------|------|
| 广告/营销 | 3 | 2.5% |
| 分析/追踪 | 3 | 2.5% |
| CDN/基础设施 | 1 | 0.8% |
| 微软/Windows 遥测 | 10 | 8.3% |
| 社交/分享 | 3 | 2.5% |
| 电商/支付 | 3 | 2.5% |
| 隐私/安全 | 7 | 5.8% |
| 其他 | 90 | 75.0% |

### 分类置信度分布

> 高置信度=注册域名精确匹配(PSL)，可直接信任；中置信度=子域名前缀匹配，建议人工确认；低置信度=无法分类，需外部API或人工判断。

| 置信度等级 | 数量 | 占比 |
|-----------|------|------|
| 高置信度 (注册域名匹配) | 26 | 21.7% |
| 中置信度 (子域名前缀) | 4 | 3.3% |
| 低置信度 (无法分类) | 90 | 75.0% |

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
| `msirouter.login` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `plex.direct` | 🟡 可疑 | 其他 | 0.00 | 解析到私有/回环 IP: ['0.0.0.0'] | HaGeZi's DNS Rebind Protection |
| `router.asus.com` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `speedport.ip` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `mwlogin.net` | ⚪ 未知 | 其他 | 0.00 | DNS 查询失败 (timeout)，但威胁情报无命中 | HaGeZi's DNS Rebind Protection |
| `tplinkdeco.net` | ⚪ 未知 | 其他 | 0.00 | DNS 查询失败 (timeout)，但威胁情报无命中 | HaGeZi's DNS Rebind Protection |
| `tplinklogin.net` | ⚪ 未知 | 其他 | 0.00 | DNS 查询失败 (timeout)，但威胁情报无命中 | HaGeZi's DNS Rebind Protection |
| `3gppnetwork.org` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `acer-connect.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
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
| `cudy.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
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
| `homeylocal.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `hostkarma.junkemailfilter.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `img.ads.tvb.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `insideruser.microsoft.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ipv4only.arpa` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `log.mmstat.com` | 🟢 安全 | CDN/基础设施 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `mailspike.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `mijnmodem.kpn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `miwifi.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `msftconnecttest.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `my.meraki.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `myunraid.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `news-app.abumedia.yql.yahoo.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `nokiawifi.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `nordspam.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `orbilogin.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `orbilogin.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
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
| `tendawifi.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tj.gov.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tongji.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tongji.edu.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tor.dan.me.uk` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `torexit.dan.me.uk` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkap.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkmodem.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkplc.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkrepeater.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkwifi.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplogin.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tracker.eu.org` | 🟢 安全 | 广告/营销 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tube.e.kuaishou.com` | 🟢 安全 | 社交/分享 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `uceprotect.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `uland.taobao.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `uribl.com` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `widget.intercom.io` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `zyxel.box` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |

## 十、规则语法支持度

| 规则类型 | 语法示例 | 状态 | 处理方式 | 数量 |
|---------|---------|------|---------|------|
| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | 2,120,689 |
| 通配符 | `||*.example.com^` | ✅ 支持 | 聚合覆盖子域 | 0 |
| Allow 白名单 | `@@||example.com^` | ✅ 支持 | 分离到 whitelist.txt | 121 |
| 正则 | `/ads.*/` | ✅ 保留 | 原样保留 | 61 |
| IP 规则 | `||8.8.8.8^` | ✅ 支持 | 按域名字符串处理 | 74 |
| Hosts | `0.0.0.0 example.com` | ✅ 支持 | 转换为 `||domain^` | - |
| $ 修饰符 | `||x.com^$important` | ✅ 保留 | 保留修饰符，纳入去重键，跳过聚合，$important 抗白名单 | 5 |
| CSS/JS | `##.ad` | ❌ 丢弃 | DNS 层不支持 | 0 |

## 十一、域名后缀 Top 20

| 后缀 | 规则数 |
|------|--------|
| eu.cc | 41,299 |
| fbcdn.net | 9,208 |
| whatsapp.net | 5,603 |
| hl.cn | 2,779 |
| cloudfront.net | 2,591 |
| pages.dev | 2,170 |
| wixstudio.com | 1,971 |
| web.app | 1,967 |
| firebaseapp.com | 1,894 |
| amazonaws.com | 1,575 |
| run.app | 1,264 |
| weebly.com | 1,179 |
| r2.dev | 1,096 |
| vercel.app | 1,063 |
| opik.net | 767 |
| lovable.app | 759 |
| co.com | 740 |
| workers.dev | 583 |
| sa.com | 577 |
| edgeone.dev | 557 |

## 十二、性能与诊断

| 指标 | 数值 |
|------|------|
| 总耗时 | — |
| 源成功率 | 17/17 |
| 缓存命中 | — |
| 精确去重 | 669,245 |
| 规范化去重 | 4,858 |
| 正则去重 | 0 |
| 质量过滤丢弃 | 37 |
| 模式丢弃 | 1,044 |
| CSS 丢弃 | 0 |
| 本次新增域名 | 0 |
| 本次移除域名 | 0 |
| 平均域名长度 | 17.5 字符 |
| 最短/最长域名 | 2 / 221 字符 |

---
*AdGuard Rules Merger V7 · 自动生成 · 内容版本 bb8030323543*
