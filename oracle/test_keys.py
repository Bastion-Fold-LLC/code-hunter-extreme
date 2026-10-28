import requests, sys, os
sys.path.insert(0, '/home/phantomcore/oracle-main-extracted/oracle-main')
import oracle_programs as op

# --- HackerOne: 406 = needs Accept: text/html or no Accept override ---
print("=== HackerOne ===")
cookies = op._cdp_get_cookies('hackerone.com')
for accept in ['text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', '*/*', 'application/json']:
    r = requests.get('https://hackerone.com/opportunities/all.json?offers_bounties=true&page=1&per_page=3',
        headers={'User-Agent':'Mozilla/5.0','Accept':accept,'X-Requested-With':'XMLHttpRequest'},
        cookies=cookies, timeout=8)
    print(f'  Accept={accept[:30]}: {r.status_code} | {r.text[:100]}')

# --- Intigriti: use JWT as Bearer (we have it in .env) ---
print("\n=== Intigriti with JWT Bearer ===")
jwt = os.environ["INTIGRITI_JWT"]  # loaded from .env — never hardcode a live session token
cookies_i = op._cdp_get_cookies('app.intigriti.com')
for url in [
    'https://api.intigriti.com/external/researcher/programs?limit=5',
    'https://api.intigriti.com/external/researcher/programs?pgSize=5&pgNumber=1',
]:
    r = requests.get(url, headers={'Authorization':f'Bearer {jwt}','Accept':'application/json',
        'User-Agent':'Mozilla/5.0'}, cookies=cookies_i, timeout=8)
    print(f'  {r.status_code} {url.split(".com")[1][:50]} | {r.text[:150]}')

# --- HackenProof: check their actual API routes from the network tab ---
print("\n=== HackenProof ===")
cookies_hp = op._cdp_get_cookies('hackenproof.com')
for url in [
    'https://hackenproof.com/api/v1/researcher/bug-bounty-programs',
    'https://hackenproof.com/api/v1/bug-bounty-programs',
    'https://hackenproof.com/api/programs/public',
    'https://hackenproof.com/bug-bounty',
    'https://hackenproof.com/api/v1/programs?type=bug_bounty',
]:
    r = requests.get(url, headers={'User-Agent':'Mozilla/5.0','Accept':'application/json'},
        cookies=cookies_hp, timeout=8)
    print(f'  {r.status_code} {url.split(".com")[1][:50]} | {r.text[:100]}')
