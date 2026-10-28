#!/usr/bin/env bash
# Oracle recall benches — bring up, initialise, verify, tear down.
#
#   benches/bringup.sh up     start containers, init state, verify auth (fail loud)
#   benches/bringup.sh down   stop and remove containers + volumes
#   benches/bringup.sh check  assert all three benches answer + auth works
#
# "up" is idempotent and does the stateful setup the recall fixtures in
# tests/test_p14_bench_recall.py depend on:
#   - DVWA : create/reset the schema via setup.php, then prove admin/password
#   - pygoat: migrate + create the persistent p14tester operator account
# No silent fallback: any step that cannot be proven exits non-zero and says why.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE=(docker compose -f "$HERE/docker-compose.yml")

JUICE="http://127.0.0.1:3000"
DVWA="http://127.0.0.1:8080"
PYGOAT="http://127.0.0.1:8000"

PYGOAT_USER="p14tester"
PYGOAT_PASS="Testpass123!"

log()  { printf '  \033[36m[benches]\033[0m %s\n' "$*"; }
die()  { printf '  \033[31m[benches] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

# Poll a URL until it answers with any HTTP status (service is listening).
wait_http() {
  local url="$1" name="$2" tries="${3:-60}"
  log "waiting for $name ($url) ..."
  for ((i = 0; i < tries; i++)); do
    if curl -fsS -o /dev/null --max-time 4 "$url" 2>/dev/null \
       || curl -sS -o /dev/null --max-time 4 "$url" 2>/dev/null; then
      log "$name is up"
      return 0
    fi
    sleep 3
  done
  die "$name did not come up at $url after $((tries * 3))s"
}

init_dvwa() {
  # DVWA needs its schema created once via setup.php before login works.
  local jar token
  jar="$(mktemp)"
  token="$(curl -sS -c "$jar" "$DVWA/setup.php" \
    | grep -oE "user_token' value='[0-9a-f]+'" | grep -oE "[0-9a-f]{32}" | head -1)" \
    || true
  [ -n "$token" ] || die "DVWA setup.php exposed no user_token (image not ready?)"
  log "DVWA: creating/resetting schema"
  curl -sS -b "$jar" -c "$jar" -o /dev/null \
    --data-urlencode "create_db=Create / Reset Database" \
    --data-urlencode "user_token=$token" \
    "$DVWA/setup.php"
  # Prove the exact login the recall fixture performs (admin/password -> 302).
  local login ltok code
  login="$(curl -sS -c "$jar" "$DVWA/login.php")"
  ltok="$(printf '%s' "$login" | grep -oE "user_token' value='[0-9a-f]+'" | grep -oE "[0-9a-f]{32}" | head -1)"
  [ -n "$ltok" ] || die "DVWA login.php exposed no user_token after setup"
  code="$(curl -sS -b "$jar" -c "$jar" -o /dev/null -w '%{http_code}' \
    --data-urlencode "username=admin" --data-urlencode "password=password" \
    --data-urlencode "Login=Login" --data-urlencode "user_token=$ltok" \
    "$DVWA/login.php")"
  # DVWA answers a successful login with a 302 redirect to index.php.
  [ "$code" = "302" ] || die "DVWA admin/password login did not 302 (got $code)"
  log "DVWA: admin login verified"

  # Plant the exposed-.git misconfig the recall map documents (dvwa-exposure-git-*):
  # the canonical image serves no .git, so replicate the real "repo cloned into
  # docroot, served by the webserver" exposure. Idempotent; verified on the wire.
  log "DVWA: planting exposed .git in docroot"
  "${COMPOSE[@]}" exec -T dvwa sh -c '
    set -e
    mkdir -p /var/www/html/.git
    printf "ref: refs/heads/master\n" > /var/www/html/.git/HEAD
    cat > /var/www/html/.git/config <<EOF
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/digininja/DVWA.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
	remote = origin
	merge = refs/heads/master
EOF
    chmod -R a+r /var/www/html/.git' || die "DVWA .git planting failed"
  for p in /.git/HEAD /.git/config; do
    c="$(curl -sS -o /dev/null -w '%{http_code}' "$DVWA$p")"
    [ "$c" = "200" ] || die "DVWA $p not served after planting (got $c)"
  done
  log "DVWA: exposed .git verified on the wire"
}

init_pygoat() {
  # pygoat registration is sometimes walled, so the recall fixture falls back
  # to a persistent operator account — create it idempotently in the container.
  log "pygoat: migrate + ensure $PYGOAT_USER account"
  # pygoat's container runs manage.py from a subdir (WORKDIR /app, python3).
  "${COMPOSE[@]}" exec -T pygoat python3 pygoat/manage.py migrate --noinput >/dev/null \
    || die "pygoat migrate failed"
  "${COMPOSE[@]}" exec -T pygoat python3 pygoat/manage.py shell <<PY || die "pygoat user create failed"
from django.contrib.auth import get_user_model
U = get_user_model()
u, created = U.objects.get_or_create(username="$PYGOAT_USER", defaults={"email": "$PYGOAT_USER@t.co"})
u.set_password("$PYGOAT_PASS")
u.is_active = True
u.save()
print("pygoat user ready:", u.username, "created" if created else "existing")
PY
  # Prove the fixture's CSRF login path reaches a lab (mirrors _pygoat_login).
  local jar csrf code
  jar="$(mktemp)"
  csrf="$(curl -sS -c "$jar" "$PYGOAT/login/" | grep -oE 'csrfmiddlewaretoken" value="[^"]+"' | sed -E 's/.*value="([^"]+)"/\1/' | head -1)"
  [ -n "$csrf" ] || die "pygoat login page exposed no csrf token"
  code="$(curl -sS -b "$jar" -c "$jar" -o /dev/null -w '%{http_code}' \
    -e "$PYGOAT/login/" \
    --data-urlencode "csrfmiddlewaretoken=$csrf" \
    --data-urlencode "username=$PYGOAT_USER" \
    --data-urlencode "password=$PYGOAT_PASS" \
    "$PYGOAT/login/")"
  [ "$code" = "302" ] || die "pygoat $PYGOAT_USER login did not 302 (got $code)"
  log "pygoat: $PYGOAT_USER login verified"
}

cmd_up() {
  command -v docker >/dev/null || die "docker not found on PATH"
  log "starting containers"
  "${COMPOSE[@]}" up -d
  wait_http "$JUICE/" "juice-shop"
  wait_http "$DVWA/login.php" "dvwa"
  wait_http "$PYGOAT/login/" "pygoat"
  init_dvwa
  init_pygoat
  log "all benches up and verified"
}

cmd_down() {
  log "tearing down containers + volumes"
  "${COMPOSE[@]}" down -v --remove-orphans
}

cmd_check() {
  # Non-mutating: the gate calls this to confirm the benches are live before
  # trusting a recall run. Fails loud if any bench is missing.
  curl -fsS -o /dev/null --max-time 5 "$JUICE/" || die "juice-shop not reachable"
  curl -fsS -o /dev/null --max-time 5 "$DVWA/login.php" || die "dvwa not reachable"
  curl -fsS -o /dev/null --max-time 5 "$PYGOAT/login/" || die "pygoat not reachable"
  log "all three benches reachable"
}

case "${1:-}" in
  up)    cmd_up ;;
  down)  cmd_down ;;
  check) cmd_check ;;
  *)     die "usage: $0 {up|down|check}" ;;
esac
