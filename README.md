# ScamShield

An explainable, privacy-minded scam-checking app for Indian users. It combines transparent rules with a locally running, corpus-trained SMS classifier, highlights its signals, and offers number checks, family alerts, a community radar, and short learning games.

## Quick start (Windows)

1. Install Python 3.10 or newer from python.org and select **Add Python to PATH**.
2. Unzip the project folder.
3. Open the `scamshield` folder inside the unzipped folder if it contains another nested folder.
4. Double-click `run.bat` and allow the Windows Firewall prompt on a trusted private network.
5. Open `http://localhost:8000`; keep the black server window open while using the app.

Mac/Linux: run `./run.sh`. Any platform: `python server.py`. The server uses only Python's standard library; no install step or npm is needed. It binds to `0.0.0.0:8000` and prints the local Wi-Fi address for phone access.

## Optional integrations

Edit `.env` next to `server.py`, then restart the app. `TELEGRAM_TOKEN` starts the optional Telegram bot in a second window; `XAI_API_KEY` enables the explicit “send redacted text to Grok” action; `XAI_MODEL` selects the xAI model and defaults to `latest`. Blank values disable those features. Never share this folder with a populated secrets file.

For Family Shield, create a code, then open its topic link on the guardian's phone and tap **Subscribe**. The free ntfy app can also subscribe to topic `scamshield-<code>`. Keep the code private: it is the notification topic name. The automatic alert includes only the scam type, not the message.

## Troubleshooting

- **“python is not recognized”**: reinstall Python and check **Add Python to PATH**.
- **Windows Firewall prompt**: allow access on your trusted private network if you want the phone-on-Wi-Fi feature.
- **Unzip created a nested folder**: open the inner `scamshield` folder and double-click the `run.bat` there.
- **Port 8000 is busy**: close the other app using it, or set `PORT=8001` in the environment before launch.
- **No phone connection**: both devices must be on the same Wi-Fi, and the firewall must allow Python on a private network.

## Privacy and number scoring

Message text is analyzed in memory by the local rule engine and ML classifier; the message is not written to disk or logged by ScamShield. The trained model has no external inference call. `state.json` stores aggregate counts, anonymous radar metadata, alert metadata, community report counts, and one-way hashed reporter keys; it never stores message text or raw IP addresses. Family codes are secrets. Radar can be disabled with the private toggle.

Number and UPI scores are transparent heuristics, not proof and not a lookup of who owns an account. Phone signals: foreign country code +40; 140 telemarketing series +30; invalid Indian mobile format +30; six repeated digits +20. UPI signals: bait word in the handle +50; unfamiliar provider +15 (weak signal); handle of 3 characters or fewer +10. Each community report adds 25, up to 60; three reports force a score of at least 70. Phone numbers normalize to their last ten digits and UPI IDs to lowercase. Thresholds match message checks: below 25 safe, 25–54 caution, 55+ scam. A clean result is not proof.

## Honest limitations

The text model is trained from deduplicated public SMS corpora with separate `ham`, `spam`, and `smishing` labels. It uses word and character n-grams, TF-IDF weighting, and a three-class logistic classifier. The compressed model runs locally with Python's standard library; NumPy is needed only when retraining. A fixed held-out split and per-class precision, recall, F1, accuracy, and confusion matrix are written by the training script. The app displays smishing likelihood, while the existing rule engine remains the explainable baseline and the ML estimate can only raise the final score. The source corpora are English-heavy and dated; performance on new scam campaigns, regional languages, and code-mixed text can differ substantially. A probability is not proof, and number reputation is not identity verification. Live feeds, Grok, ntfy, OCR, speech transcription, and Telegram rely on internet and external services. See [ML_DATA_SOURCES.md](ML_DATA_SOURCES.md) for attribution and training instructions.

### Retrain the model

Download `Dataset_5971.csv` from the Mendeley source and the UCI `SMSSpamCollection` file, extract the latter from its ZIP, then run:

```powershell
python -m pip install numpy
python train_ml_model.py --mendeley path\to\Dataset_5971.csv --uci path\to\SMSSpamCollection
```

This writes `ml_model.json.gz` and `ml_model.json.metrics.json`. The training script removes normalized duplicate messages before splitting; overlapping UCI rows use the more detailed Mendeley label. Raw messages stay outside the app repository.

### Test on your PC

The following need live browser/device/network access and were not verified by the automated checks: desktop and phone-width visual review of all tabs and flows, screenshot OCR (CDN and language data), microphone transcription, real ntfy delivery, real Grok call and model name, Telegram bot delivery, live phishing-feed downloads, and phone access over Wi-Fi. Chrome sends speech audio to Google for transcription. OCR runs in your browser; the screenshot is not uploaded to ScamShield.

Potential next improvements: collect a recent, consented Indian-language SMS corpus, measure performance by language and campaign over time, and add links to current official I4C/RBI advisories.
