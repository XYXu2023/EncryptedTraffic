# Ablation Report

RandomForest was retrained for each feature set.

- A_basic: accuracy=0.5046, weighted_f1=0.5080, features=17
- B_basic_temporal: accuracy=0.5169, weighted_f1=0.5233, features=21
- C_basic_temporal_burst: accuracy=0.5276, weighted_f1=0.5311, features=25
- D_all_features: accuracy=0.5322, weighted_f1=0.5467, features=39

Best feature set: `D_all_features`.
