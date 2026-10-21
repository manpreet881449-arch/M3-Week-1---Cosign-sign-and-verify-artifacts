#!/usr/bin/env python3
import datetime, json, pathlib, re, subprocess, sys
from packaging.version import InvalidVersion, Version

if len(sys.argv) != 2:
    sys.exit("Usage: dep_bot.py <sbom.json>")

sbom = sys.argv[1]
req = pathlib.Path("app/requirements.txt")


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def run(*cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


# 1. Scan the SBOM
scan = json.loads(
    run("grype", f"sbom:{sbom}", "-o", "json", capture_output=True, text=True).stdout
)

# 2. Collect the lowest safe version per package (max across all its CVEs)
fixes = {}  # name -> (version, [cve ids])
for m in scan["matches"]:
    fix = m["vulnerability"].get("fix", {})
    if fix.get("state") != "fixed" or not fix.get("versions"):
        continue
    installed = m["artifact"]["version"]
    try:
        cands = [v for v in fix["versions"] if Version(v) > Version(installed)]
        if not cands:
            continue
        best = min(cands, key=Version)
    except InvalidVersion:
        continue
    name = norm(m["artifact"]["name"])
    old_best, cves = fixes.get(name, (best, []))
    if Version(best) > Version(old_best):
        old_best = best
    fixes[name] = (old_best, cves + [m["vulnerability"]["id"]])

if not fixes:
    print("No fixable CVEs")
    sys.exit(0)

# 3. Rewrite requirements.txt
lines, changed = [], []
for line in req.read_text().splitlines():
    m = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([^\s;#]+)", line)
    if m and norm(m.group(1)) in fixes:
        new_ver, cves = fixes[norm(m.group(1))]
        lines.append(f"{m.group(1)}=={new_ver}")
        changed.append(
            f"{m.group(1)}: {m.group(2)} -> {new_ver} ({', '.join(sorted(set(cves)))})"
        )
    else:
        lines.append(line)

if not changed:
    print("Fixable CVEs found, but none are pinned in app/requirements.txt")
    sys.exit(0)

branch = f"bot/cve-fixes-{datetime.date.today()}"
run("git", "checkout", "-b", branch)
req.write_text("\n".join(lines) + "\n")

# 4. Sandbox test: build normally, run with NO network in a throwaway container
try:
    run("docker", "build", "-t", "bot-test", "app/")
    run("docker", "run", "--rm", "--network", "none", "bot-test", "python", "-m", "pytest")
except subprocess.CalledProcessError:
    run("git", "checkout", "--", "app/requirements.txt")
    run("git", "checkout", "-")
    run("git", "branch", "-D", branch)
    sys.exit("Sandbox tests FAILED - no PR opened")

# 5. Commit, push, open PR
run("git", "add", "app/requirements.txt")
run("git", "commit", "-m", "fix(deps): patch CVEs from SBOM scan")
run("git", "push", "-u", "origin", branch)
run("gh", "pr", "create", "--base", "main", "--title", "Automated CVE patches",
    "--body", "Bot changes:\n" + "\n".join(f"- {c}" for c in changed))
