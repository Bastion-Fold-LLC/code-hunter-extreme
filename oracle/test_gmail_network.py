import urllib.request, json, websocket, time

port = 9223
tabs = json.loads(urllib.request.urlopen(f'http://127.0.0.1:{port}/json/list', timeout=3).read())
gmail = next((t for t in tabs if 'mail.google.com' in t.get('url','') and t.get('type')=='page'), None)
print('Tab:', gmail['url'][:70] if gmail else 'none')

ws = websocket.create_connection(gmail['webSocketDebuggerUrl'], timeout=20)
ws.settimeout(1)
mid = [0]
def nid(): mid[0]+=1; return mid[0]

ws.send(json.dumps({'id':nid(),'method':'Network.enable'}))
time.sleep(0.3)
try: ws.recv()
except: pass

ws.send(json.dumps({'id':nid(),'method':'Page.navigate','params':{'url':'https://mail.google.com/mail/u/0/#inbox'}}))

urls_seen = set()
deadline = time.time() + 10
while time.time() < deadline:
    try:
        raw = json.loads(ws.recv())
    except:
        continue
    m = raw.get('method','')
    p = raw.get('params',{})
    if m == 'Network.requestWillBeSent':
        u = p.get('request',{}).get('url','')
        if '//' in u:
            host = u.split('/')[2]
        else:
            host = u[:40]
        if host not in urls_seen:
            urls_seen.add(host)
            print('HOST:', host[:70])
ws.close()
print('Done')
