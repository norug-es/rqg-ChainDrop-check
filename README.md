<p align="center">
  <img src="../assets/logo-norug.svg" alt="NoRug.es logo" width="360" />
</p>

<p align="center">
  <a href="./README-SP.md"><img src="https://img.shields.io/badge/ES-%F0%9F%87%AA%F0%9F%87%B8%20Espa%C3%B1ol-C60B1E?style=for-the-badge" alt="Spanish documentation" /></a>
  <a href="./README-EN.md"><img src="https://img.shields.io/badge/EN-%F0%9F%87%AC%F0%9F%87%A7%20English-012169?style=for-the-badge" alt="English documentation" /></a>
  <a href="../LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT License" /></a>
</p>

# Tools Index

## Español

La carpeta `tools/` contiene una herramienta de inspección rápida y de solo lectura para detectar indicadores conocidos de **ChainDrop** en repositorios JavaScript/TypeScript antes de ejecutar instalaciones, builds o abrir el proyecto como entorno de confianza.

### Documentación

- [Guía completa en español](./README-SP.md)
- [Full guide in English](./README-EN.md)

## English

The `tools/` directory contains a fast, read-only inspection tool for detecting known **ChainDrop** indicators in JavaScript/TypeScript repositories before running installs, builds, or opening the project as a trusted environment.

### Documentation

- [Guía completa en español](./README-SP.md)
- [Full guide in English](./README-EN.md)

## What it does

- Scans for suspicious persistence artifacts and lifecycle scripts.
- Checks package manifests and lockfiles for known ChainDrop-related versions.
- Searches for known IoCs, GitHub markers, and execution triggers.
- Produces a quick result: `NO KNOWN`, `REVIEW`, or `QUARANTINE / INVESTIGATE`.

## Qué hace

- Busca artefactos sospechosos de persistencia y lifecycle scripts.
- Revisa manifests y lockfiles para versiones asociadas a ChainDrop.
- Detecta IoCs conocidos, marcadores de GitHub y disparadores de ejecución.
- Devuelve un resultado rápido: `NO KNOWN`, `REVIEW` o `QUARANTINE / INVESTIGATE`.

## Files

- `README-SP.md`: documentación completa en español.
- `README-EN.md`: full documentation in English.
- `rqg-chaindrop-check.ps1`: script para Windows / PowerShell.
- `rqg-chaindrop-check.sh`: script para Linux, macOS, WSL y Bash.
