# ML data sources and model card

## Training data

The model combines two public labeled SMS collections. Texts are normalized and deduplicated before the validation split; where a message appears in both, the more detailed Mendeley label is kept.

1. Sandhya Mishra and Devpriya Soni, *SMS Phishing Dataset for Machine Learning and Pattern Recognition*, Mendeley Data, version 1 (2022), DOI [10.17632/f45bkkt8pr.1](https://doi.org/10.17632/f45bkkt8pr.1). The source contains 5,971 rows labeled ham, spam, and smishing. Dataset page: <https://data.mendeley.com/datasets/f45bkkt8pr/1>. Licensed CC BY 4.0.
2. Almeida, T. A. and Hidalgo, J. M. G., *SMS Spam Collection*, UCI Machine Learning Repository (2011), DOI [10.24432/C5CC84](https://doi.org/10.24432/C5CC84). The source contains 5,574 rows labeled ham or spam. Dataset page: <https://archive.ics.uci.edu/dataset/228/sms>.

The training script expects the original Mendeley CSV and extracted UCI `SMSSpamCollection` TSV as local files. It does not copy raw data into this repository or the deployed service. Attribution is retained here; consult the source pages for their current license terms and citation details.

## Model card

- **Task:** classify SMS text as ham, unsolicited spam, or smishing. ScamShield uses the smishing probability as an advisory signal.
- **Method:** hashed word unigrams/bigrams and character 3–5-grams; train-set IDF; L2-normalized features; three-class multinomial logistic model trained with stochastic gradient descent.
- **Inference:** Python standard library only. Text is scored in memory; no model API or hosted inference call is made.
- **Validation:** the training script uses a seeded, stratified 80/20 holdout after normalized-text deduplication. It writes per-class precision/recall/F1, accuracy, macro F1, and the confusion matrix to a metrics file. See the bundled model's validation report and regenerate it with the documented command when the model is retrained.
- **Current holdout:** 1,304 messages; 93.79% accuracy and 82.20% macro F1. On 110 held-out smishing messages, precision was 78.85%, recall 74.55%, and F1 76.64%. The confusion matrix and remaining class results are in `ml_model.json.metrics.json`.
- **Known limits:** the source corpora are English-heavy, include older messages and generic spam, and may not represent current Indian campaigns or all languages and scripts. Train/test separation is by normalized exact text, not by sender, campaign, or time. Reported metrics are an offline benchmark, not a guarantee for live traffic.
- **Human guidance:** use the rule explanations and independent verification. A model category or probability is not proof that a sender is malicious or safe.
