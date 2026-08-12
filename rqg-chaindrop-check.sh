#!/usr/bin/env bash
set -u

ROOT="${1:-.}"
cd "$ROOT" || exit 3

SELF_RE='rqg-chaindrop-check(\-v1\.1)?\.(ps1|sh)$'
EXCLUDE_RE='(^|/)(node_modules|\.git|\.rqg|threat-intel/feeds|rules)(/|$)'

printf "\n============================================\n"
printf " RQG ChainDrop Quick Check v1.1 - Bash\n"
printf "============================================\n"
printf "Repo: %s\n\n" "$(pwd)"

critical=0
warning=0

section(){ printf "\n---- %s ----\n" "$1"; }

is_excluded() {
  local f="$1"
  [[ "$f" =~ $SELF_RE ]] && return 0
  [[ "$f" =~ $EXCLUDE_RE ]] && return 0
  return 1
}

section "TEST 1/4 - Suspicious files and persistence locations"

test1=""
while IFS= read -r -d '' f; do
  is_excluded "$f" && continue
  case "$f" in
    */setup.mjs|*/math_init.js|*/Math_Symbol.js|*/router_runtime.js|*/.claude/*|*/.vscode/*|*/.github/workflows/*)
      test1+="$f"$'\n'
      ;;
  esac
done < <(find . -type f -print0 2>/dev/null)

if [[ -n "$test1" ]]; then
  printf "%s" "$test1"
  printf "[WARN] Review the files above manually.\n"
  warning=$((warning+1))
else
  printf "[OK] No suspicious filenames or persistence locations found.\n"
fi

section "TEST 2/4 - package.json lifecycle scripts"

found_package=0
while IFS= read -r -d '' f; do
  is_excluded "$f" && continue
  found_package=1
  if command -v node >/dev/null 2>&1; then
    if node -e '
      const fs=require("fs");
      const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
      const keys=["preinstall","install","postinstall","prepare"];
      let hit=false;
      for(const k of keys){
        if(p.scripts && p.scripts[k]){
          console.log(`[WARN] ${process.argv[1]}: ${k} = ${p.scripts[k]}`);
          hit=true;
        }
      }
      process.exit(hit?0:1);
    ' "$f"; then
      warning=$((warning+1))
    fi
  else
    grep -nE '"(preinstall|install|postinstall|prepare)"[[:space:]]*:' "$f" || true
  fi
done < <(find . -type f -name package.json -print0 2>/dev/null)

(( found_package == 0 )) && printf "[INFO] No package.json found in repository tree.\n"

section "TEST 3/4 - Known affected package/version and setup indicators"

pattern='("preinstall"|setup\.mjs|keyv[^[:alnum:]].*6\.0\.0|flat-cache[^[:alnum:]].*6\.1\.24|file-entry-cache[^[:alnum:]].*11\.1\.6|cacheable-request[^[:alnum:]].*13\.0\.20|cacheable[^[:alnum:]].*2\.5\.1|@cacheable/memory[^[:alnum:]].*2\.2\.1|cache-manager[^[:alnum:]].*7\.2\.10|@cacheable/node-cache[^[:alnum:]].*3\.1\.2|@cacheable/utils[^[:alnum:]].*2\.5\.1|@cacheable/net[^[:alnum:]].*2\.1\.1|ecto[^[:alnum:]].*5\.0\.1)'
found_pkg_ioc=0

while IFS= read -r -d '' f; do
  is_excluded "$f" && continue
  if grep -nEi "$pattern" "$f" 2>/dev/null; then
    printf "  -> %s\n" "$f"
    found_pkg_ioc=1
  fi
done < <(find . -type f \( -name package.json -o -name package-lock.json -o -name npm-shrinkwrap.json -o -name pnpm-lock.yaml -o -name yarn.lock \) -print0 2>/dev/null)

if (( found_pkg_ioc == 1 )); then
  printf "[CRITICAL] ChainDrop-relevant package/version or setup indicator found.\n"
  critical=$((critical+1))
else
  printf "[OK] No known affected package/version or setup indicator found.\n"
fi

section "TEST 4/4 - ChainDrop IoCs and behavioral markers"

ioc='awqhnjewqjkl\.icu|npm-cache\.com|pypi-get\.com|js-mirror\.com|thebeautifulmarchoftime|thebeautifulsnadsoftime|IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients|0xE1f2395ee43e45A1556EC6438a88c31B83493103|0x53ed5143|toJSON[[:space:]]*\([[:space:]]*secrets[[:space:]]*\)|runOn.*folderOpen|SessionStart|_NODE_RUNTIME_INIT=1|tmp\.dpkg_14527\.lock|gh-token-monitor'
found_ioc=0

while IFS= read -r -d '' f; do
  is_excluded "$f" && continue
  size=$(wc -c < "$f" 2>/dev/null || echo 999999999)
  [[ "$size" -ge 5242880 ]] && continue
  if grep -nEi "$ioc" "$f" 2>/dev/null; then
    printf "  -> %s\n" "$f"
    found_ioc=1
  fi
done < <(find . -type f -print0 2>/dev/null)

if (( found_ioc == 1 )); then
  printf "[CRITICAL] One or more ChainDrop IoCs/behavioral markers were found.\n"
  critical=$((critical+1))
else
  printf "[OK] No known ChainDrop IoCs found.\n"
fi

printf "\n============================================\n"
printf " SUMMARY\n"
printf "============================================\n"

if (( critical > 0 )); then
  printf "RESULT: QUARANTINE / INVESTIGATE\n"
  printf "Critical groups: %d | Warning groups: %d\n" "$critical" "$warning"
  exit 2
elif (( warning > 0 )); then
  printf "RESULT: REVIEW\n"
  printf "Critical groups: 0 | Warning groups: %d\n" "$warning"
  exit 1
else
  printf "RESULT: NO KNOWN CHAINDROP INDICATORS FOUND\n"
  printf "This is not a guarantee that the repository is safe.\n"
  exit 0
fi