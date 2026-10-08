#!/usr/bin/env bash
# Detect XCSSET (Xcode project malware) and VS Code autorun malware before commit/push.
#
# Usage:
#   scripts/check-xcsset.sh            scan the working tree (tracked + untracked files)
#   scripts/check-xcsset.sh --rev SHA  scan the tree of a commit (used by the pre-push hook)
#
# Exit 1 if infection markers are found.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SCAN_DIR="$ROOT"
TMP_DIR=""
cleanup() { if [[ -n "$TMP_DIR" ]]; then rm -rf "$TMP_DIR"; fi; }
trap cleanup EXIT

if [[ "${1:-}" == "--rev" ]]; then
  rev="${2:?usage: check-xcsset.sh --rev <commit>}"
  TMP_DIR="$(mktemp -d)"
  git archive "$rev" | tar -x -C "$TMP_DIR"
  SCAN_DIR="$TMP_DIR"
fi

cd "$SCAN_DIR"
found=0
flag() { echo "XCSSET indicator: $*"; found=1; }

# Strings seen in XCSSET payloads, including the variant removed in 526670a
# (encoded build settings A1ECAD1/AC0C26C/AE6D436/A45ED5A/A6E983A run from a
# "Build Target Libraries" Run Script phase, C2 applerelay.ru / mindelgate.ru).
PATTERNS=(
  'xxd -p -r'
  'base64 --decode'
  'base64 -d'
  'printf xx3d'
  'printf xvxd'
  'printf xOxd'
  'base764'
  'A1ECAD1'
  'AC0C26C'
  'AB8F749'
  'A8CDBB7'
  'A45ED5A'
  'A6E983A'
  'AE6D436'
  'AE76EDB'
  'p=xcode_'
  'sh -c \\"\$\{A'
  '\| *sh *\)'
  'curl '
  'osascript'
  'applerelay\.ru'
  'mindelgate\.ru'
  'cdnamz\.ru'
  'bulknames\.ru'
  'fiddlejoy\.ru'
  'tcpnet\.ru'
  'sinusnet\.ru'
  'cdcache\.ru'
  'Provision Library Executable'
  'Compile Code Assets'
  'Build Target Libraries'
  'Link Libraries Executable'
  'Copy Target Symbols'
)

pbxprojs=()
while IFS= read -r -d '' f; do pbxprojs+=("$f"); done < <(
  find . -name 'project.pbxproj' -not -path './.git/*' -not -path './.build/*' -print0)

if [[ ${#pbxprojs[@]} -eq 0 ]]; then
  echo "BLOCKED: no project.pbxproj found. A missing pbxproj means the tree is"
  echo "incomplete or was replaced (do not treat that as clean)."
  exit 1
fi

for f in "${pbxprojs[@]}"; do
  for pat in "${PATTERNS[@]}"; do
    grep -E -q -- "$pat" "$f" && flag "matched /$pat/ in $f"
  done
  # This repo has no CocoaPods or legitimate script phases or build rules.
  grep -q 'isa = PBXShellScriptBuildPhase' "$f" && flag "Run Script build phase in $f"
  grep -q 'isa = PBXBuildRule' "$f" && flag "custom build rule in $f"
  # Payloads hidden off-screen behind long runs of whitespace, or in huge lines.
  grep -E -q '[[:space:]]{80,}' "$f" && flag "long whitespace run (hidden content) in $f"
  awk 'length > 1000 { exit 1 }' "$f" || flag "line longer than 1000 chars in $f"
done

# Scheme pre/post actions can run shell scripts on build/run.
while IFS= read -r -d '' f; do
  grep -E -q 'ExecutionAction|scriptText' "$f" && flag "scheme script action in $f"
done < <(find . -name '*.xcscheme' -not -path './.git/*' -print0)

# Decoy folders XCSSET drops into projects.
while IFS= read -r -d '' f; do
  flag "suspicious file/dir: $f"
done < <(find . -not -path './.git/*' \( -name '.xcassets' -o -name 'xcassets' -o -name 'project.xworkspace' \
  -o -name 'Asset.xcasset' -o -name 'xcassets.folder' -o -name '*.llf' -o -name '*.bat' -o -name '*.ps1' \
  -o -name '*.command' -o -name '*.scpt' -o -name '*.applescript' -o -name '*.js' -o -name '*.cjs' -o -name '*.mjs' \
  -o -name 'branch_structure.json' -o -path './public' \) -print0)

# Empty README.md files are bait to trigger a malicious *.md build rule.
while IFS= read -r -d '' f; do
  flag "empty README bait: $f"
done < <(find . -not -path './.git/*' -name 'README.md' -size 0 -print0)

# VS Code tasks that auto-run when the folder is opened.
while IFS= read -r -d '' f; do
  grep -q 'folderOpen' "$f" && flag "VS Code autorun task (runOn: folderOpen) in $f"
  grep -E -q 'node .*\.(llf|woff2?|ttf|eot|svg)' "$f" && flag "VS Code task runs a disguised payload in $f"
done < <(find . -path '*/.vscode/*.json' -not -path './.git/*' -print0)

# .gitignore entries used to hide the malware's push scripts.
if [[ -f .gitignore ]] && grep -E -q 'push\.bat|\.bat$|branch_structure' .gitignore; then
  flag ".gitignore hides malware push scripts"
fi

if [[ "$found" -ne 0 ]]; then
  echo ""
  echo "BLOCKED: malware markers detected. Do not commit or push."
  echo "Remove the injected build phase/rule/settings, .vscode autorun task, and"
  echo "decoy files, then re-run: scripts/check-xcsset.sh"
  exit 1
fi

echo "check-xcsset: clean"
