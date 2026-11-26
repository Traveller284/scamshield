"""Optional Telegram interface; requires TELEGRAM_TOKEN in .env."""
import json, os, time, urllib.parse, urllib.request, secrets
import server

TOKEN=os.environ.get('TELEGRAM_TOKEN','')
API=f'https://api.telegram.org/bot{TOKEN}/'
LANG={}
def call(method,params=None,timeout=35):
    data=urllib.parse.urlencode(params or {}).encode()
    with urllib.request.urlopen(urllib.request.Request(API+method,data=data),timeout=timeout) as r:
        return json.loads(r.read().decode())
def send(chat,text):
    call('sendMessage',{'chat_id':chat,'text':text[:4000]},timeout=12)
def handle(msg):
    chat=str(msg['chat']['id']); text=msg.get('text') or msg.get('caption') or ''
    if not text:return
    cmd=text.split()[0].lower().split('@')[0] if text.startswith('/') else ''
    langs={'/hi':'hi','/kn':'kn','/ta':'ta','/te':'te','/en':'en'}
    if cmd in langs:
        LANG[chat]=langs[cmd];send(chat,'Language set. Forward or send a suspicious message to check it.');return
    lang=LANG.get(chat,'en')
    if cmd=='/start' or cmd=='/help':
        send(chat,'ScamShield bot: send or forward a suspicious message for a risk score. Commands: /en /hi /kn /ta, /number <phone or UPI>, /guardian. A safe result is not a guarantee.');return
    if cmd=='/number':
        value=' '.join(text.split()[1:])
        if not value:send(chat,'Usage: /number <phone or UPI ID>');return
        d=server.lookup(value)
        details='\n'.join(f"+{s['points']} {s['text']}" for s in d['signals']) or 'No risk signals found.'
        send(chat,f"Number/UPI risk: {d['score']}/100 · {d['level']}\n{details}\nA clean result does not prove who owns this number.");return
    if cmd=='/guardian':
        code=secrets.token_hex(3);server.guard_set(code,chat)
        send(chat,f'Your Telegram guardian code is {code}. Enter this 6-character code in Family Shield on the protected device. Keep it private.');return
    d=server.analyse(text,lang,dry=True)
    reasons='\n'.join('• '+x['label'] for x in d['flags']) or 'No strong scam signals found.'
    send(chat,f"{d['verdict']} · {d['score']}/100\n{reasons}\n\n{d['advice']}\n\nThis is a rule-based estimate, not a guarantee.")
def main():
    if not TOKEN:print('TELEGRAM_TOKEN is blank in .env; bot is disabled.');return
    offset=0;print('ScamShield Telegram bot is running.')
    while True:
        try:
            result=call('getUpdates',{'offset':offset,'timeout':25},timeout=35)
            for update in result.get('result',[]):
                offset=update['update_id']+1
                if 'message' in update:
                    try:handle(update['message'])
                    except Exception as e:print('Bot update could not be processed:',e)
        except Exception as e:print('Telegram connection issue:',e);time.sleep(4)
if __name__=='__main__':main()

