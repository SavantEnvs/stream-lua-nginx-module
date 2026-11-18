#!/usr/bin/env bash
#
# Runs the nginx built by mayhem/build.sh (normal flags, stream-lua-nginx-module compiled in) and checks known
# request -> response pairs through real TCP connections, so a build whose Lua API no longer behaves fails here.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

NGINX=$SRC/mayhem/build/oracle/sbin/nginx
DEPS=/opt/toolchains/deps
if [ ! -x "$NGINX" ]; then
  echo "missing $NGINX: mayhem/build.sh did not build it" >&2
  emit_ctrf "stream-lua-nginx-module" 0 1
  exit 1
fi

TMP=$(mktemp -d /tmp/slnm-test.XXXXXX)
PORT=$(( 20000 + RANDOM % 20000 ))
sed -e "s#@TMP@#$TMP#g" -e "s#@PORT@#$PORT#g" \
    -e "s#@CORE@#$(echo $DEPS/lua-resty-core-*/src)#" \
    -e "s#@LRU@#$(echo $DEPS/lua-resty-lrucache-*/src)#" \
    mayhem/test/nginx.conf > "$TMP/nginx.conf"

"$NGINX" -p "$TMP" -c "$TMP/nginx.conf" > "$TMP/stdout.log" 2>&1 &
NGX_PID=$!
trap 'kill "$NGX_PID" 2>/dev/null; wait "$NGX_PID" 2>/dev/null; rm -rf "$TMP"' EXIT

# send one request line, print the first response line
ask() {
  (
    exec 3<>"/dev/tcp/127.0.0.1/$PORT" || exit 1
    printf '%s\n' "$1" >&3
    IFS= read -r -t 10 resp <&3
    printf '%s' "$resp"
  ) 2>/dev/null
}

up=0
for _ in $(seq 1 50); do
  if [ -n "$(ask 'md5 hello')" ]; then up=1; break; fi
  kill -0 "$NGX_PID" 2>/dev/null || break
  sleep 0.2
done

passed=0; failed=0
check() {  # <request line> <expected response line>
  local got
  got=$(ask "$1")
  if [ -n "$got" ] && [ "$got" = "$2" ]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL $1: expected [$2] got [$got]" >&2
  fi
}

if [ "$up" = 1 ]; then
  check "b64enc hello" "aGVsbG8="
  check "b64dec aGVsbG8=" "hello"
  check "unesc a%20b%2Fc" "a b/c"
  check "esc" "a%20b%26c%2Fd"
  check "match" "123-xyz|123|xyz"
  check "gsub" "hell[o] w[o]rld 2"
  check "md5 hello" "5d41402abc4b2a76b9719d911017c592"
  check "sha1 hello" "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
  check "crc32 hello" "907060870"
  check "shdict world" "world|42"
  check "lexer" "}{ ]] }"
  check $'recv\nfoo--bar--baz' "foo|bar"
else
  echo "nginx did not start; see:" >&2
  tail -20 "$TMP/error.log" "$TMP/stdout.log" >&2
  failed=1
fi

emit_ctrf "stream-lua-nginx-module" "$passed" "$failed"
