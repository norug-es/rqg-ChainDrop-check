# RQG Local Audit

`tools/rqg-local-audit.py` es un auditor portable para repositorios locales.
Escanea el árbol del proyecto, descarga uno o varios feeds IoC por HTTPS y
emite un diagnóstico de riesgo sin ejecutar el código del repo.

## Uso

```bash
python tools/rqg-local-audit.py . --feed-url https://rqg.norug.es/rqg-ioc-feed.json
```

Si prefieres un feed desde disco:

```bash
python tools/rqg-local-audit.py . --feed-file path/to/ioc-feed-v1.json
```

## Qué revisa

- coincidencias directas contra el feed descargado;
- nombres de archivo y rutas sospechosas;
- workflows, scripts y configuraciones de IDE/agent;
- lifecycle scripts de `package.json`;
- versiones npm marcadas en el feed;
- integridad del artefacto npm, si el repo contiene paquetes publicables y no
  usas `--skip-registry`.

## Salida

- `0`: sin señales conocidas;
- `1`: revisar;
- `2`: cuarentena;
- `3`: error de ruta o carga de feeds.

## Exclusiones

Para evitar auto-coincidencias, el script no audita sus propios feeds ni el
data de threat intel de este repo:

- `tools/rqg-local-audit.py`
- `app/data/ioc-feed-v1.json`
- `app/data/chaindrop.json`
- `threat-intel/feeds/`

Eso no impide que audite el resto del árbol del proyecto.
