# Split Summary

- Total flows: 2630
- Train flows: 1575
- Val flows: 403
- Test flows: 652

## Label Distribution
- Train: {'browser': 221, 'chat': 184, 'cloud': 98, 'download': 100, 'shopping': 366, 'social': 268, 'video': 338}
- Val: {'chat': 26, 'cloud': 14, 'download': 14, 'shopping': 52, 'social': 38, 'video': 259}
- Test: {'browser': 156, 'chat': 53, 'cloud': 29, 'download': 29, 'shopping': 105, 'social': 78, 'video': 202}

## Leakage Control Notes
The splitter groups by `capture_file` when a label has at least three captures. For labels with fewer captures, it falls back to stratified flow-level splitting and records this limitation.

## Per Label Strategy
- browser: grouped_by_capture, train=221, val=0, test=156
- chat: flow_stratified_capture_group_insufficient, train=184, val=26, test=53
- cloud: flow_stratified_capture_group_insufficient, train=98, val=14, test=29
- download: flow_stratified_capture_group_insufficient, train=100, val=14, test=29
- shopping: flow_stratified_capture_group_insufficient, train=366, val=52, test=105
- social: flow_stratified_capture_group_insufficient, train=268, val=38, test=78
- video: grouped_by_capture, train=338, val=259, test=202
