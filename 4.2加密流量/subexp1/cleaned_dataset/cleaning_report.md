# Cleaning Report

## Overview

- Raw capture JSON files processed: 12
- Raw flow records before filtering: 4328
- Clean/retained flow records written: 3123
- Filtered background flow records: 1205
- Retained uncertain flow records: 1649

## Retained Flow Counts By Label

- browser: 534
- chat: 300
- cloud: 136
- download: 164
- shopping: 528
- social: 486
- video: 975

## Retained Flow Counts By Environment

- direct: 3003
- proxy: 120

## Filtered Background Types

- local_or_private_only: 882
- insufficient_signal_or_single_local_flow: 176
- known_system_or_office_background_domain;local_or_private_only: 74
- known_system_or_office_background_domain: 65
- local_control_protocol;local_or_private_only: 8

## Cleaning Rules

- Flow construction: bidirectional five-tuple `(src_ip, dst_ip, src_port, dst_port, protocol)` from packet-level Wireshark JSON.
- Label normalization: filenames and source folders were mapped to stable `scene`, `app_name`, `platform`, and `environment` values.
- DNS/TLS/HTTP/QUIC domain hints were retained when they matched the target app/scene or proxy/VPN path.
- Local control traffic such as ARP, mDNS, LLMNR, NBNS, ICMPv6, multicast/local-only flows, and non TCP/UDP packets were treated as background.
- Known system/background domains including Office, Teams, OneDrive, Windows update/connectivity checks, Apple/iCloud, and browser telemetry/update endpoints were filtered unless they were explicitly part of the labeled target class.
- Proxy/VPN transport links were retained as valid environment-path flows when proxy/VPN ports were observed.
- Encrypted flows with no visible domain but enough packet evidence were retained as `is_background=unknown` for conservative downstream review.

## Uncertain Retained Samples

- Total uncertain retained flows: 1649
- Android_pinduoduo_000001 172.20.10.2 -> 111.31.205.53:3478 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000002 172.20.10.2 -> 111.31.205.53:3478 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000005 172.20.10.2 -> 202.89.233.100:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000006 2409:8900:9981:83f2:f0a2:c0b7:c623:ca1a -> 2001::4b7e:96d2:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000008 172.20.10.2 -> 108.160.166.148:443 (shopping, direct): domain_not_in_target_or_background_rules
- Android_pinduoduo_000009 172.20.10.2 -> 111.62.49.133:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000010 2409:8900:9981:83f2:f0a2:c0b7:c623:ca1a -> 2001::4b7e:96d2:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000011 172.20.10.2 -> 108.160.166.148:443 (shopping, direct): domain_not_in_target_or_background_rules
- Android_pinduoduo_000012 172.20.10.2 -> 183.201.248.49:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000013 172.20.10.2 -> 183.201.248.49:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000014 172.20.10.2 -> 183.201.248.49:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000015 172.20.10.3 -> 101.35.204.35:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000016 172.20.10.3 -> 101.35.204.35:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000017 172.20.10.3 -> 101.35.204.35:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000018 172.20.10.3 -> 101.35.204.35:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000019 172.20.10.2 -> 111.132.33.107:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000020 172.20.10.2 -> 183.201.248.49:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000022 172.20.10.2 -> 111.13.110.159:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000023 172.20.10.2 -> 183.201.244.115:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000024 172.20.10.2 -> 183.201.244.115:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000025 172.20.10.2 -> 183.201.244.115:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000026 172.20.10.2 -> 111.13.104.62:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000027 172.20.10.3 -> 111.132.32.107:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000028 172.20.10.2 -> 183.201.244.115:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000029 172.20.10.2 -> 183.201.244.115:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000030 172.20.10.2 -> 111.33.110.146:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000032 2409:8900:9981:83f2:d8b5:cdb9:d640:2206 -> 240c:409f::3:0:359:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000033 2409:8900:9981:83f2:d8b5:cdb9:d640:2206 -> 240c:409f::3:0:359:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000034 172.20.10.3 -> 114.110.97.97:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000035 172.20.10.3 -> 114.110.97.97:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000036 172.20.10.3 -> 114.110.97.97:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000050 2409:8900:9981:83f2:d8b5:cdb9:d640:2206 -> 240c:409f::3:0:359:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000052 172.20.10.3 -> 101.35.204.35:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000058 2409:8c0c:310:901:3::72 -> 2409:8900:9981:83f2:f0a2:c0b7:c623:ca1a:65219 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000061 119.3.160.204 -> 172.20.10.2:64482 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000062 2409:8900:9981:83f2:d8b5:cdb9:d640:2206 -> 240c:409f::3:0:359:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000063 172.20.10.3 -> 101.35.204.35:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000064 2409:8900:9981:83f2:d8b5:cdb9:d640:2206 -> 2409:8c1e:8ff0:e:::443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000066 2409:8900:9981:83f2:d8b5:cdb9:d640:2206 -> 240c:409f::3:0:359:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000067 172.20.10.2 -> 103.213.5.44:20067 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000068 2409:8900:9981:83f2:d8b5:cdb9:d640:2206 -> 2402:4e00:1411:201:0:9964:ba21:5a41:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000071 2409:8900:9981:83f2:d8b5:cdb9:d640:2206 -> 2402:4e00:1411:201:0:9964:ba21:5a41:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000074 2409:8900:9981:83f2:d8b5:cdb9:d640:2206 -> 2402:4e00:1411:201:0:9964:ba21:5a41:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000076 172.20.10.3 -> 101.35.204.35:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000079 172.20.10.3 -> 36.152.46.3:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000082 172.20.10.3 -> 114.110.97.97:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000083 2409:8900:9981:83f2:d8b5:cdb9:d640:2206 -> 2409:8c1e:8ff0:e:::443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000084 20.205.69.80 -> 172.20.10.2:60877 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000085 172.20.10.3 -> 101.35.204.35:80 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Android_pinduoduo_000087 2409:8900:9981:83f2:f0a2:c0b7:c623:ca1a -> 2603:1030:40c:e::1:443 (shopping, direct): encrypted_or_ip_only_flow_no_domain_observed
- Additional uncertain flows omitted from report: 1599

## Sparse Or Noisy Captures

- None flagged by the valid-flow ratio rule.

## Capture Summary

- pinduoduo.pcapng: platform=mobile, environment=direct, scene=shopping, total_flows=765, valid=528, filtered=237, unknown=377
- QQ.pcapng: platform=mobile, environment=direct, scene=chat, total_flows=273, valid=241, filtered=32, unknown=52
- QQmusic.pcapng: platform=mobile, environment=direct, scene=video, total_flows=247, valid=197, filtered=50, unknown=111
- rednotes.pcapng: platform=mobile, environment=direct, scene=social, total_flows=561, valid=486, filtered=75, unknown=121
- tiktok.pcapng: platform=mobile, environment=direct, scene=video, total_flows=644, valid=525, filtered=119, unknown=287
- browse_without_VPN.pcapng: platform=pc, environment=direct, scene=browser, total_flows=403, valid=264, filtered=139, unknown=88
- chat.pcapng: platform=pc, environment=direct, scene=chat, total_flows=96, valid=59, filtered=37, unknown=45
- cloud.pcapng: platform=pc, environment=direct, scene=cloud, total_flows=250, valid=136, filtered=114, unknown=136
- download.pcapng: platform=pc, environment=direct, scene=download, total_flows=239, valid=164, filtered=75, unknown=138
- video.pcapng: platform=pc, environment=direct, scene=video, total_flows=479, valid=253, filtered=226, unknown=177
- browse_no_proxy.pcapng: platform=pc, environment=direct, scene=browser, total_flows=229, valid=150, filtered=79, unknown=63
- browse_proxy.pcapng: platform=pc, environment=proxy, scene=browser, total_flows=142, valid=120, filtered=22, unknown=54
