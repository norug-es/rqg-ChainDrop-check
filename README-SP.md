<p align="center">
  <img src="./assets/logo-norug.svg" alt="NoRug.es logo" width="360" />
</p>



# RQG-norug.es ChainDrop Quick Check

Herramienta de inspección rápida para detectar indicadores conocidos y patrones sospechosos relacionados con **ChainDrop** en repositorios JavaScript/TypeScript antes de ejecutar instalaciones, builds o abrir el proyecto como entorno de confianza.

Incluye dos scripts:

* `rqg-chaindrop-check.ps1` → Windows / PowerShell
* `rqg-chaindrop-check.sh` → Linux, macOS, WSL y entornos Bash

> Estos scripts son de **solo lectura**. No borran archivos, no modifican el repositorio y no ejecutan `npm install`, `npm run`, builds ni código del proyecto.

---

## Objetivo

El flujo recomendado es:

```text
Repositorio
    ↓
RQG-norug.es Quick Check
    ↓
¿IoC / patrones sospechosos?
   ├─ Sí → QUARANTINE / INVESTIGATE
   └─ No → continuar con revisión normal
```

El scanner realiza cuatro grupos de comprobaciones:

1. Artefactos y mecanismos de persistencia sospechosos.
2. Lifecycle scripts de npm.
3. Paquetes/versiones asociados a ChainDrop.
4. IoC y marcadores conductuales conocidos.

Un resultado limpio **no garantiza que un repositorio sea seguro**. El objetivo es detectar rápidamente evidencias conocidas antes de ejecutar código.

---

# Windows — PowerShell

## Requisitos

* Windows 10/11 o Windows Server.
* PowerShell 5.1 o PowerShell 7+.
* Node.js es recomendable para interpretar correctamente `package.json`, aunque algunas comprobaciones funcionan sin él.

## Ejecución desde la raíz del repositorio

Coloca:

```text
tools/
└── rqg-chaindrop-check.ps1
```

Ejecuta:

```powershell
.\tools\rqg-chaindrop-check.ps1
```

También puedes analizar otra carpeta:

```powershell
.\tools\rqg-chaindrop-check.ps1 `
  -Path "C:\Dev\proyecto"
```

## Si PowerShell bloquea el script

Puedes permitirlo solo para la sesión actual:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Y volver a ejecutar:

```powershell
.\tools\rqg-chaindrop-check-v1.1.ps1
```

No es necesario cambiar permanentemente la política del sistema.

---

# Linux / macOS / WSL — Bash

## Requisitos

* Bash.
* `find`.
* `grep`.
* Node.js recomendado.

Coloca:

```text
tools/
└── rqg-chaindrop-check-v1.1.sh
```

Dale permisos:

```bash
chmod +x tools/rqg-chaindrop-check-v1.1.sh
```

Ejecuta desde la raíz:

```bash
./tools/rqg-chaindrop-check-v1.1.sh
```

También puedes indicar una ruta:

```bash
./tools/rqg-chaindrop-check-v1.1.sh /opt/projects/repository
```

En WSL:

```bash
./tools/rqg-chaindrop-check-v1.1.sh /mnt/c/Dev/proyecto
```

---

# Qué busca exactamente

## TEST 1/4 — Persistencia y archivos sospechosos

Busca nombres y ubicaciones utilizadas o relacionadas con las técnicas observadas en ChainDrop.

Entre ellas:

```text
setup.mjs
math_init.js
Math_Symbol.js
router_runtime.js
```

También inspecciona:

```text
.vscode/
.claude/
.github/workflows/
```

Estas ubicaciones son especialmente relevantes porque una campaña de supply-chain puede persistir más allá de `npm install`.

Por ejemplo:

```text
.vscode/tasks.json
```

puede contener:

```json
"runOn": "folderOpen"
```

haciendo que una tarea se ejecute al abrir el repositorio.

Del mismo modo:

```text
.claude/settings.json
```

puede incluir hooks como:

```text
SessionStart
```

capaces de lanzar código cuando se inicia una sesión del agente.

Este test produce normalmente:

```text
[OK]
```

o:

```text
[WARN]
```

porque la mera existencia de `.vscode`, `.claude` o workflows no significa que sean maliciosos.

---

# TEST 2/4 — Lifecycle scripts de npm

Analiza todos los `package.json` encontrados en el repositorio.

Busca principalmente:

```text
preinstall
install
postinstall
prepare
```

Ejemplo:

```json
{
  "scripts": {
    "preinstall": "node setup.mjs"
  }
}
```

Los lifecycle scripts son importantes porque pueden ejecutarse automáticamente durante operaciones como:

```bash
npm install
```

Un `preinstall` no es automáticamente malware.

Muchos proyectos legítimos los utilizan.

Por eso el scanner lo clasifica inicialmente como:

```text
WARN / REVIEW
```

y debe correlacionarse con otras evidencias.

Por ejemplo:

```text
preinstall
+
setup.mjs
+
IoC ChainDrop
```

es mucho más grave que un simple:

```text
prepare: husky
```

---

# TEST 3/4 — Versiones npm relacionadas con ChainDrop

El scanner revisa:

```text
package.json
package-lock.json
npm-shrinkwrap.json
pnpm-lock.yaml
yarn.lock
```

y busca versiones asociadas al conjunto de paquetes comprometidos que RQG-norug.es está siguiendo.

Actualmente incluye entre otros:

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

También busca:

```text
setup.mjs
```

y referencias a:

```text
"preinstall"
```

dentro de los manifests y lockfiles.

Una coincidencia aquí genera:

```text
CRITICAL
```

porque ya no estamos hablando únicamente de una técnica genérica, sino de una combinación conocida de paquete y versión.

---

# TEST 4/4 — IoC y comportamiento ChainDrop

Esta es la comprobación más específica.

Busca indicadores conocidos de compromiso y señales características de la campaña.

## Infraestructura C2

```text
awqhnjewqjkl.icu
npm-cache.com
pypi-get.com
js-mirror.com
```

La presencia de estos valores dentro del código debe investigarse inmediatamente.

---

## Resolución C2 mediante Ethereum

Busca:

```text
0xE1f2395ee43e45A1556EC6438a88c31B83493103
```

y:

```text
0x53ed5143
```

Estos valores permiten detectar el mecanismo de resolución dinámica de infraestructura aunque el dominio de mando y control cambie posteriormente.

---

## Marcadores GitHub

Busca:

```text
thebeautifulmarchoftime
```

```text
thebeautifulsnadsoftime
```

y el marcador altamente distintivo:

```text
IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients
```

Estos strings han sido asociados con mecanismos de fallback y exfiltración mediante GitHub.

Una coincidencia completa es una señal muy fuerte.

---

## GitHub Actions

Busca:

```text
toJSON(secrets)
```

especialmente dentro de:

```text
.github/workflows/
```

Ejemplo sospechoso:

```yaml
env:
  ALL_SECRETS: ${{ toJSON(secrets) }}
```

Esto puede exponer de forma masiva secretos disponibles al runner de GitHub Actions.

---

## VS Code

Busca:

```text
folderOpen
```

especialmente asociado a:

```text
.vscode/tasks.json
```

Ejemplo:

```json
{
  "runOptions": {
    "runOn": "folderOpen"
  }
}
```

Esto puede convertir simplemente abrir el repositorio en un disparador de ejecución.

---

## Claude Code

Busca:

```text
SessionStart
```

especialmente dentro de:

```text
.claude/settings.json
```

Esto permite detectar hooks que podrían lanzar código al comenzar una sesión.

---

## Runtime Node / Bun

Busca:

```text
_NODE_RUNTIME_INIT=1
```

Este indicador puede estar relacionado con mecanismos utilizados para controlar relanzamientos del runtime.

También busca:

```text
tmp.dpkg_14527.lock
```

como artefacto de locking observado.

---

## Persistencia gh-token-monitor

Busca referencias a:

```text
gh-token-monitor
```

relacionadas con posibles rutas como:

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

La aparición aislada debe analizarse en contexto, pero combinada con otros indicadores ChainDrop aumenta significativamente la severidad.

---

# Exclusiones automáticas

El scanner evita analizar determinadas rutas para reducir falsos positivos.

Actualmente excluye:

```text
node_modules/
.git/
.rqg/
threat-intel/feeds/
rules/
```

También excluye sus propios scripts:

```text
rqg-chaindrop-check.ps1
rqg-chaindrop-check.sh
```

Esto es importante porque los scripts contienen literalmente los IoC que utilizan para buscar amenazas.

Sin esta exclusión, el scanner se detectaría a sí mismo como ChainDrop.

---

# Interpretación del resultado

## Resultado limpio

```text
RESULT: NO KNOWN CHAINDROP INDICATORS FOUND
```

Código de salida:

```text
0
```

Significa:

> No se han encontrado indicadores ChainDrop conocidos mediante estas cuatro comprobaciones.

No significa:

> El repositorio es 100 % seguro.

---

## REVIEW

```text
RESULT: REVIEW
```

Código:

```text
1
```

Puede ocurrir por elementos como:

```text
postinstall
prepare
.vscode/
.claude/
GitHub workflows
```

que necesitan revisión manual pero pueden ser totalmente legítimos.

---

## QUARANTINE / INVESTIGATE

```text
RESULT: QUARANTINE / INVESTIGATE
```

Código:

```text
2
```

Significa que se ha encontrado al menos un grupo de indicadores críticos.

En ese caso:

**No ejecutar:**

```bash
npm install
npm ci
npm run build
npm test
pnpm install
yarn install
bun install
```

hasta investigar.

---

# Si `npm install` ya fue ejecutado

Si aparecen IoC críticos después de haber ejecutado una versión comprometida, no asumas que borrar `node_modules` resuelve el problema.

Debes considerar comprometidas potencialmente:

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

La respuesta correcta debería incluir:

```text
1. Aislar el equipo.

2. Revocar y rotar credenciales desde otro host limpio.

3. Revisar GitHub Actions, branches, deploy keys, Apps y OAuth tokens.

4. Revisar repositorios modificados.

5. Limpiar o reconstruir runners/workstations comprometidos.

6. Invalidar cachés de CI/CD.

7. Revisar paquetes publicados desde las cuentas afectadas.
```

---

# Uso recomendado en el workflow

En lugar de:

```text
git clone
code .
npm install
```

usar:

```text
git clone
    ↓
RQG-norug.es ChainDrop Quick Check
    ↓
RQG-norug.es completo
    ↓
revisión
    ↓
abrir IDE
    ↓
instalar dependencias
```

Idealmente:

```text
GitHub URL
    ↓
rqg.norug.es
    ↓
LOW / REVIEW / HIGH / QUARANTINE
```

y estos scripts quedan como una herramienta rápida de inspección local.

---

# Ejemplo Windows

```powershell
PS C:\Dev\proyecto> .\tools\rqg-chaindrop-check-v1.1.ps1
```

Resultado esperado:

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

# Ejemplo Linux/macOS

```bash
./tools/rqg-chaindrop-check.sh .
```

O:

```bash
./tools/rqg-chaindrop-check.sh ~/projects/my-repository
```

---

# Limitaciones

Este quick scanner no sustituye:

* sandbox dinámico;
* EDR/antivirus;
* análisis forense;
* SBOM;
* Registry Integrity;
* comparación npm tarball ↔ GitHub;
* análisis de provenance;
* CodeGraph;
* dependency reputation;
* análisis de procesos y red.

Es una **primera barrera de seguridad local**.

Para un análisis completo debe utilizarse RQG-norug.es:

```text
Static Intelligence
+
Registry Integrity
+
Threat Intelligence
+
CodeGraph
+
Attack Paths
+
Blast Radius
+
Runtime Intelligence
```

---

## Proyecto

**RQG-norug.es — Repo Quarantine Gateway**

Seguridad preventiva para repositorios, dependencias, IDEs, agentes de IA y cadenas de suministro.

**norug.es**
