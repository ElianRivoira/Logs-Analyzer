# 🔍 Agente de Análisis de Logs con LangChain

Un agente inteligente que analiza logs de Google Cloud Platform usando LangChain y Gemini (sin requerir Vertex AI) para proporcionar insights detallados y sugerencias de solución.

## 🚀 Características

- **Análisis Inteligente de Logs**: Usa Gemini para entender y analizar logs complejos
- **Búsqueda de Código Fuente**: Integración con GitHub para encontrar el código relacionado con los errores
- **Memoria Conversacional**: Mantiene contexto entre consultas usando ConversationBufferMemory
- **Análisis de Patrones**: Detecta patrones recurrentes y genera estadísticas
- **Consultas Flexibles**: Soporta tanto queries estructuradas como lenguaje natural
- **RAG para Mapeo Servicio-Repo**: Sistema de recuperación para encontrar repositorios correspondientes

## 📋 Requisitos Previos

- Python 3.8+
- Cuenta de Google Cloud Platform con acceso a:
  - Cloud Logging API (para leer logs)
- Credenciales de Google Cloud configuradas en el sistema:
  - `gcloud auth application-default login` (recomendado)
  - O ejecución en un entorno de Google Cloud
- API Key de Gemini (gratuita, obtenla en https://makersuite.google.com/app/apikey)
- Token de GitHub (opcional, para búsqueda de código)

## 🛠️ Instalación

1. **Clonar el repositorio**
```bash
git clone <tu-repo>
cd logs-analyzer-agent
```

2. **Instalar dependencias**
```bash
pip install -r requirements.txt
```

3. **Configurar credenciales de Google Cloud**

El agente usa las credenciales por defecto del sistema. Configúralas con:
```bash
gcloud auth application-default login
```

4. **Configurar variables de entorno**

Crear un archivo `.env`:
```env
# Requerido
GEMINI_API_KEY=tu-api-key-de-gemini

# Opcional (para búsqueda en GitHub)
GITHUB_TOKEN=tu-github-token
GITHUB_ORG=tu-organizacion

# Opcional (si quieres especificar un proyecto por defecto)
GCP_PROJECT_ID=tu-project-id-default
```

5. **Configurar mapeo servicio-repositorio**

Editar `service_repo_config.json` con tus servicios y repositorios.

## 📖 Uso

### Modo Interactivo

```bash
python enhanced_agent_loader.py
```

Luego selecciona la opción 1 para modo interactivo.

### Query Estructurada

```
proyecto: uma-development-ar
servicio: uma-megalith
periodo: últimas 2 horas
severidad: ERROR
tipo: prescription
```

### Query en Lenguaje Natural

```
Muéstrame todos los errores de autenticación del servicio auth en las últimas 24 horas
```

### Uso Programático

```python
from enhanced_agent_loader import EnhancedLogAnalyzerWithConfig

# Crear el agente
analyzer = EnhancedLogAnalyzerWithConfig(project_id="tu-project-id")

# Analizar logs
result = analyzer.analyze_logs("""
    servicio: uma-megalith
    severidad: ERROR
    periodo: última hora
""")

print(result)
```

## 🔧 Configuración Avanzada

### Agregar Nuevos Servicios

Edita `service_repo_config.json`:

```json
{
  "service": "nuevo-servicio",
  "repo": "repo-del-servicio",
  "description": "Descripción del servicio",
  "tech_stack": "Stack tecnológico",
  "main_path": "src/",
  "log_patterns": {
    "error_location": "src/utils/logger.js",
    "api_routes": "src/routes/"
  }
}
```

### Personalizar Herramientas

Puedes agregar nuevas herramientas en el método `_create_tools()`:

```python
def my_custom_tool(param: str) -> str:
    """Mi herramienta personalizada"""
    # Tu lógica aquí
    return resultado

tools.append(Tool(
    name="my_custom_tool",
    func=my_custom_tool,
    description="Descripción de la herramienta"
))
```

## 📊 Salida del Análisis

El agente proporciona:

1. **Resumen Ejecutivo**: Overview del problema encontrado
2. **Estadísticas**:
   - Distribución por severidad
   - Tipos de errores
   - Servicios afectados
3. **Código Fuente**: Snippets relevantes de GitHub
4. **Recomendaciones**: Sugerencias específicas de solución
5. **Link a Logs Explorer**: Para análisis más profundo

## 🐛 Troubleshooting

### Error: "No se encontraron credenciales"
- Ejecuta `gcloud auth application-default login`
- O asegúrate de estar ejecutando en un entorno de Google Cloud con permisos adecuados
- Solo necesitas permisos para Cloud Logging API

### Error: "GEMINI_API_KEY no configurado"
- Asegúrate de tener la variable `GEMINI_API_KEY` en tu archivo `.env`
- Puedes obtener una API key gratuita en https://makersuite.google.com/app/apikey

### Error: "No se puede conectar a GitHub"
- Verifica que `GITHUB_TOKEN` esté configurado
- Asegúrate de que el token tenga permisos de lectura en los repositorios

### Los logs no se encuentran
- Verifica que el project_id sea correcto
- Asegúrate de que el servicio esté generando logs
- Revisa que el período de tiempo sea válido
- Confirma que tienes permisos para leer logs en el proyecto

## 🤝 Contribuir

1. Fork el proyecto
2. Crea tu feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push al branch (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Ver `LICENSE` para más detalles.