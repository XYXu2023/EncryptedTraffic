# Online Replay Evaluation

- First N packets: 20
- Total labeled flows: 2630
- Accuracy: 0.5677
- Macro F1: 0.5667
- Weighted F1: 0.5570

## True Label Distribution
- browser: 377
- chat: 263
- cloud: 141
- download: 143
- shopping: 523
- social: 384
- video: 799

## Predicted Label Distribution
- browser: 469
- chat: 165
- cloud: 157
- download: 240
- shopping: 520
- social: 464
- video: 615

## Notes
- This evaluates the online first-N-packet feature path, not the offline complete-flow classifier.
- Live traffic accuracy still requires manually labeled live captures or a controlled browsing script.
