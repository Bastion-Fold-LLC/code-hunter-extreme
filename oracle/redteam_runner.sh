#!/bin/bash
LOG=/home/phantomcore/oracle/redteam_run.log
exec > "$LOG" 2>&1

echo "=== ORACLE RED-TEAM RUN ===" 
date

cd /home/phantomcore/oracle

# 1. Start testbed
python -c "
import http.server, threading, sys, time
sys.path.insert(0, 'tests')
import bad_code_app
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), bad_code_app.VulnerableHandler)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()
open('/home/phantomcore/oracle/rt_port.txt','w').write(str(port))
print(f'TESTBED PORT={port}', flush=True)
while True: time.sleep(30)
" &
TESTBED_PID=$!
sleep 3
PORT=$(cat /home/phantomcore/oracle/rt_port.txt)
echo "Testbed running on port $PORT (pid $TESTBED_PID)"
curl -s http://127.0.0.1:$PORT/health
echo ""

# 2. Known-bug corpus
echo ""
echo "=== PHASE 1: KNOWN-BUG CORPUS ==="
python -m pytest tests/test_known_bugs.py -v --tb=short

# 3. Full hunt pipeline
echo ""
echo "=== PHASE 2: ORACLE HUNT PIPELINE ==="
python oracle_hunter.py hunt "http://127.0.0.1:$PORT" --auto --no-cloud

# 4. Show findings
echo ""
echo "=== PHASE 3: FINDINGS ==="
find targets/ reports/ -name "finding_*.json" 2>/dev/null | while read f; do
    echo "--- $f ---"
    python -c "
import sys, json
d = json.load(open('$f'))
print('  verdict:', d.get('verify_verdict','?'))
print('  assertion_b:', str(d.get('assertion_b',''))[:100])
print('  impact:', str(d.get('impact',''))[:80])
" 2>/dev/null
done

kill $TESTBED_PID 2>/dev/null
echo ""
echo "=== DONE ==="
date
