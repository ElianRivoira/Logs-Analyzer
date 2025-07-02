# Logs Analyzer (debug_analyzer_openai.py)

Logs Analyzer es una herramienta avanzada para analizar logs de Google Cloud Platform (GCP) usando modelos de lenguaje de OpenAI (GPT-4 Turbo) y la librería LangChain. Permite búsquedas inteligentes, análisis de tendencias y agrupación de errores en logs de servicios como Cloud Run, Firestore, etc.

> **Nota:** Las credenciales de GCP se toman automáticamente de las configuradas por defecto en tu PC o servidor (por ejemplo, usando `gcloud auth application-default login`).

## Características principales

- **Búsqueda avanzada de logs**: Genera filtros automáticos a partir de descripciones en lenguaje natural o queries estructuradas.
- **Análisis de tendencias**: Identifica patrones, picos de errores y distribuciones temporales en los logs.
- **Memoria conversacional**: Mantiene el contexto de la conversación para análisis iterativos.
- **Integración con OpenAI y LangChain**: Usa modelos GPT para mejorar la interpretación y el análisis.
- **Soporte para múltiples proyectos y servicios**: Permite cambiar de proyecto GCP dinámicamente.
- **Extracción y agrupación de mensajes de error**: Limpia y agrupa mensajes similares para facilitar el diagnóstico.

## Requisitos

- Python 3.11+
- Acceso a Google Cloud Platform y permisos para leer logs
- Clave de API:
  - `OPENAI_API_KEY` (OpenAI, obligatoria)
  - `GITHUB_TOKEN` (opcional, para integración con GitHub)
- Archivo `.env` en la raíz con las variables necesarias:
  ```env
  OPENAI_API_KEY=sk-...
  GITHUB_TOKEN=ghp_...   # Opcional
  ```

## Instalación

1. Clona el repositorio y entra al directorio:
   ```bash
   git clone <url-del-repo>
   cd Logs Analyzer
   ```
2. (Opcional) Crea y activa un entorno virtual:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```
4. Crea un archivo `.env` en la raíz con tu clave de OpenAI (y opcionalmente GitHub):
   ```env
   OPENAI_API_KEY=sk-...
   GITHUB_TOKEN=ghp_...   # Opcional
   ```

## Uso

Puedes ejecutar el analizador en dos modos:

### 1. Prueba con queries predefinidas

```bash
python debug_analyzer_openai.py
```

Selecciona la opción 1 y edita la query de ejemplo en el código si lo deseas.

### 2. Modo chat interactivo

```bash
python debug_analyzer_openai.py
```

Selecciona la opción 2 para ingresar consultas en lenguaje natural de forma interactiva.

#### Ejemplos de consultas

- `project: uma-v2, service: my-service, timestamp: últimas 3 horas, severity: ERROR`
- `Buscar errores de autenticación en las últimas 24 horas en el servicio auth`
- `Logs con status_code: 500 en el último día`

## Estructura del proyecto

- `debug_analyzer_openai.py`: Analizador principal (este README cubre solo este archivo).
- `requirements.txt`: Dependencias del proyecto.

## Notas

- El filtro de logs se genera automáticamente, pero puedes ingresar filtros GCP completos si lo prefieres.
- Los resultados incluyen un resumen, tendencias y un enlace directo a Logs Explorer de GCP.
- El proyecto está pensado para facilitar el troubleshooting y acelerar la detección de problemas en entornos cloud.

## Licencia

MIT
