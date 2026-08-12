<p align="center">
  <img src="./assets/logo-norug.svg" alt="NoRug.es logo" width="360" />
</p>




# RQG-norug.es ChainDrop Quick Check

Fast inspection tool for detecting known indicators and suspicious patterns related to **ChainDrop** in JavaScript/TypeScript repositories before running installs, builds, or opening the project as a trusted environment.

It includes two scripts:

* `rqg-chaindrop-check.ps1` -> Windows / PowerShell
* `rqg-chaindrop-check.sh` -> Linux, macOS, WSL and Bash environments

> These scripts are **read-only**. They do not delete files, do not modify the repository, and do not run `npm install`, `npm run`, builds, or project code.

---

## Goal

The recommended flow is:

```text
Repository
    ↓
RQG-norug.es Quick Check
    ↓
IoC / suspicious patterns?
   ├─ Yes -> QUARANTINE / INVESTIGATE
   └─ No  -> continue with normal review
```

The scanner performs four groups of checks:

1. Suspicious persistence artifacts and mechanisms.
2. npm lifecycle scripts.
3. Packages and versions associated with ChainDrop.
4. Known IoCs and behavioral markers.

A clean result does **not** guarantee that a repository is safe. The goal is to surface known evidence quickly before executing code.

---

# Windows - PowerShell

## Requirements

* Windows 10/11 or Windows Server.
* PowerShell 5.1 or PowerShell 7+.
* Node.js is recommended to correctly interpret `package.json`, although some checks work without it.

## Run from the repository root

Place:

```text
tools/
└── rqg-chaindrop-check.ps1
```

Run:

```powershell
.\tools\rqg-chaindrop-check.ps1
```

You can also scan another folder:

```powershell
.\tools\rqg-chaindrop-check.ps1 `
  -Path "C:\Dev\project"
```

## If PowerShell blocks the script

You can allow it only for the current session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then run it again:

```powershell
.\tools\rqg-chaindrop-check.ps1
```

You do not need to permanently change the system policy.

---

# Linux / macOS / WSL - Bash

## Requirements

* Bash.
* `find`.
* `grep`.
* Node.js recommended.

Place:

```text
tools/
└── rqg-chaindrop-check.sh
```

Make it executable:

```bash
chmod +x tools/rqg-chaindrop-check.sh
```

Run it from the repository root:

```bash
./tools/rqg-chaindrop-check.sh
```

You can also pass a path:

```bash
./tools/rqg-chaindrop-check.sh /opt/projects/repository
```

In WSL:

```bash
./tools/rqg-chaindrop-check.sh /mnt/c/Dev/project
```

---

# What it looks for

## TEST 1/4 - Persistence and suspicious files

Looks for names and locations associated with techniques observed in ChainDrop.

Including:

```text
setup.mjs
math_init.js
Math_Symbol.js
router_runtime.js
```

It also inspects:

```text
.vscode/
.claude/
.github/workflows/
```

These locations are especially relevant because a supply-chain campaign can persist beyond `npm install`.

For example:

```text
.vscode/tasks.json
```

can contain:

```json
"runOn": "folderOpen"
```

causing a task to run when the repository is opened.

Likewise:

```text
.claude/settings.json
```

can include hooks such as:

```text
SessionStart
```

capable of launching code when an agent session starts.

This test normally produces:

```text
[OK]
```

or:

```text
[WARN]
```

because the mere existence of `.vscode`, `.claude`, or workflows does not mean they are malicious.

---

# TEST 2/4 - npm lifecycle scripts

Scans all `package.json` files found in the repository.

Looks mainly for:

```text
preinstall
install
postinstall
prepare
```

Example:

```json
{
  "scripts": {
    "preinstall": "node setup.mjs"
  }
}
```

Lifecycle scripts matter because they can run automatically during operations such as:

```bash
npm install
```

A `preinstall` script is not automatically malware.

Many legitimate projects use them.

That is why the scanner initially classifies it as:

```text
WARN / REVIEW
```

and it must be correlated with other evidence.

For example:

```text
preinstall
+ setup.mjs
+ IoC ChainDrop
```

is much more serious than a simple:

```text
prepare: husky
```

---

# TEST 3/4 - npm versions related to ChainDrop

The scanner reviews:

```text
package.json
package-lock.json
npm-shrinkwrap.json
pnpm-lock.yaml
yarn.lock
```

and searches for versions associated with the set of compromised packages tracked by RQG-norug.es.

Currently includes, among others:

```text
keyv@6.0.0

flat-cache@6.1.24

file-entry-cache@11.1.6

cacheable-request@13.0.20

cacheable@2.5.1

@cacheable/memory@2.2.1

cache-manager@7.2.10

@cacheable/node-cache@3.1.2

@cacheable/utils@2.5.1

@cacheable/net@2.1.1

ecto@5.0.1
```

It also looks for:

```text
setup.mjs
```

and references to:

```text
"preinstall"
```

inside manifests and lockfiles.

A match here generates:

```text
CRITICAL
```

because we are no longer talking only about a generic technique, but about a known combination of package and version.

---

# TEST 4/4 - IoC and ChainDrop behavior

This is the most specific check.

It looks for known compromise indicators and characteristic signals from the campaign.

## C2 infrastructure

```text
awqhnjewqjkl.icu
npm-cache.com
pypi-get.com
js-mirror.com
```

The presence of these values inside the code should be investigated immediately.

---

## C2 resolution via Ethereum

Looks for:

```text
0xE1f2395ee43e45A1556EC6438a88c31B83493103
```

and:

```text
0x53ed5143
```

These values help detect the dynamic infrastructure resolution mechanism even if the command-and-control domain changes later.

---

## GitHub markers

Looks for:

```text
thebeautifulmarchoftime
```

```text
thebeautifulsnadsoftime
```

and the highly distinctive marker:

```text
IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients
```

These strings have been associated with fallback and exfiltration mechanisms through GitHub.

A full match is a very strong signal.

---

## GitHub Actions

Looks for:

```text
toJSON(secrets)
```

especially inside:

```text
.github/workflows/
```

Suspicious example:

```yaml
env:
  ALL_SECRETS: ${{ toJSON(secrets) }}
```

This can expose all secrets available to the GitHub Actions runner.

---

## VS Code

Looks for:

```text
folderOpen
```

especially when associated with:

```text
.vscode/tasks.json
```

Example:

```json
{
  "runOptions": {
    "runOn": "folderOpen"
  }
}
```

This can turn simply opening the repository into an execution trigger.

---

## Claude Code

Looks for:

```text
SessionStart
```

especially inside:

```text
.claude/settings.json
```

This helps detect hooks that could launch code when a session begins.

---

## Node / Bun runtime

Looks for:

```text
_NODE_RUNTIME_INIT=1
```

This indicator may be related to mechanisms used to control runtime relaunches.

It also looks for:

```text
tmp.dpkg_14527.lock
```

as a locking artifact that was observed.

---

## gh-token-monitor persistence

Looks for references to:

```text
gh-token-monitor
```

related to possible paths such as:

```text
~/.local/bin/gh-token-monitor.sh
```

```text
~/.config/gh-token-monitor/
```

```text
~/.config/systemd/user/gh-token-monitor.service
```

```text
~/Library/LaunchAgents/com.user.gh-token-monitor.plist
```

An isolated appearance should be analyzed in context, but combined with other ChainDrop indicators it increases severity significantly.

---

# Automatic exclusions

The scanner avoids certain paths to reduce false positives.

Currently excludes:

```text
node_modules/
.git/
.rqg/
threat-intel/feeds/
rules/
```

It also excludes its own scripts:

```text
rqg-chaindrop-check.ps1
rqg-chaindrop-check.sh
```

This matters because the scripts literally contain the IoCs they use to search for threats.

Without this exclusion, the scanner would detect itself as ChainDrop.

---

# Result interpretation

## Clean result

```text
RESULT: NO KNOWN CHAINDROP INDICATORS FOUND
```

Exit code:

```text
0
```

Means:

> No known ChainDrop indicators were found by these four checks.

Does not mean:

> The repository is 100% safe.

---

## REVIEW

```text
RESULT: REVIEW
```

Code:

```text
1
```

Can happen because of items such as:

```text
postinstall
prepare
.vscode/
.claude/
GitHub workflows
```

which need manual review but may be completely legitimate.

---

## QUARANTINE / INVESTIGATE

```text
RESULT: QUARANTINE / INVESTIGATE
```

Code:

```text
2
```

Means that at least one group of critical indicators was found.

In that case:

**Do not run:**

```bash
npm install
npm ci
npm run build
npm test
pnpm install
yarn install
bun install
```

until it has been investigated.

---

# If `npm install` has already been run

If critical IoCs appear after a compromised version was already installed, do not assume that deleting `node_modules` solves the problem.

Consider the following potentially compromised:

```text
GitHub tokens
npm tokens
SSH keys
cloud credentials
Docker credentials
CI/CD secrets
.env
wallet credentials
developer tokens
```

The right response should include:

```text
1. Isolate the machine.

2. Revoke and rotate credentials from another clean host.

3. Review GitHub Actions, branches, deploy keys, Apps, and OAuth tokens.

4. Review modified repositories.

5. Clean or rebuild compromised runners/workstations.

6. Invalidate CI/CD caches.

7. Review packages published from affected accounts.
```

---

# Recommended workflow

Instead of:

```text
git clone
code .
npm install
```

use:

```text
git clone
    ↓
RQG-norug.es ChainDrop Quick Check
    ↓
RQG-norug.es full review
    ↓
manual review
    ↓
open IDE
    ↓
install dependencies
```

Ideally:

```text
GitHub URL
    ↓
rqg.norug.es
    ↓
LOW / REVIEW / HIGH / QUARANTINE
```

and these scripts remain a fast local inspection tool.

---

# Windows example

```powershell
PS C:\Dev\project> .\tools\rqg-chaindrop-check.ps1
```

Expected result:

```text
---- TEST 1/4 ----
[OK]

---- TEST 2/4 ----
[OK]

---- TEST 3/4 ----
[OK]

---- TEST 4/4 ----
[OK]

============================================
 SUMMARY
============================================

RESULT: NO KNOWN CHAINDROP INDICATORS FOUND
```

---

# Linux/macOS example

```bash
./tools/rqg-chaindrop-check.sh .
```

Or:

```bash
./tools/rqg-chaindrop-check.sh ~/projects/my-repository
```

---

# Limitations

This quick scanner does not replace:

* dynamic sandboxing;
* EDR/antivirus;
* forensic analysis;
* SBOM;
* Registry Integrity;
* npm tarball vs GitHub comparison;
* provenance analysis;
* CodeGraph;
* dependency reputation;
* process and network analysis.

It is a **first local security barrier**.

For a full analysis, use RQG-norug.es:

```text
Static Intelligence
+ Registry Integrity
+ Threat Intelligence
+ CodeGraph
+ Attack Paths
+ Blast Radius
+ Runtime Intelligence
```

---

## Project

**RQG-norug.es - Repo Quarantine Gateway**

Preventive security for repositories, dependencies, IDEs, AI agents, and supply chains.

**norug.es**
