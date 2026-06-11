# Cross Environment Report

## Results
- direct_train_direct_test: accuracy=0.5015, weighted_f1=0.5168, train=1453, test=652
- direct_train_proxy_test: accuracy=0.2787, weighted_f1=0.4359, train=1453, test=122
- direct_train_vpn_test: not available (insufficient labels or test rows)
- mixed_train_mixed_test: accuracy=0.5291, weighted_f1=0.5365, train=1575, test=652

## Interpretation Template
Compare direct-to-direct with direct-to-proxy/VPN. A lower proxy/VPN score indicates that encapsulation, proxy endpoints, or changed timing/burst patterns reduce classifier transferability. If VPN is unavailable, report it as a data limitation rather than a negative result.
