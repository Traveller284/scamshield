# ScamShield

An explainable, privacy-minded scam-checking demo for Indian users. It scores suspicious messages, highlights the signals it found, and offers number checks, family alerts, a community radar, and short learning games.

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

Message text is analyzed in memory and is not written to disk or logged. `state.json` stores aggregate counts, anonymous radar metadata, alert metadata, community report counts, and one-way hashed reporter keys; it never stores message text or raw IP addresses. Family codes are secrets. Radar can be disabled with the persistent private toggle.

Number and UPI scores are transparent heuristics, not proof and not a lookup of who owns an account. Phone signals: foreign country code +40; 140 telemarketing series +30; invalid Indian mobile format +30; six repeated digits +20. UPI signals: bait word in the handle +50; unfamiliar provider +15 (weak signal); handle of 3 characters or fewer +10. Each community report adds 25, up to 60; three reports force a score of at least 70. Phone numbers normalize to their last ten digits and UPI IDs to lowercase. Thresholds match message checks: below 25 safe, 25–54 caution, 55+ scam. A clean result is not proof.

## Honest limitations

The detector uses hand-written rules, not machine learning. It can miss new wording, code-mixed text, and languages outside the listed keyword coverage; Hindi, Kannada, Tamil, and Telugu detection is keyword-level. Number reputation is not identity verification. Live feeds, Grok, ntfy, OCR, speech transcription, and Telegram rely on internet and external services.

### Test on your PC

The following need live browser/device/network access and were not verified by the automated checks: desktop and phone-width visual review of all tabs and flows, screenshot OCR (CDN and language data), microphone transcription, real ntfy delivery, real Grok call and model name, Telegram bot delivery, live phishing-feed downloads, and phone access over Wi-Fi. Chrome sends speech audio to Google for transcription. OCR runs in your browser; the screenshot is not uploaded to ScamShield.

Potential future improvements: Bengali/Marathi coverage, more advisory patterns, a small trained classifier, and I4C/RBI advisory integration.
