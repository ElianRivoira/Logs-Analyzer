import sys
sys.path.insert(0, '/home/elian/Documentos/Logs Analyzer/.venv/lib/python3.11/site-packages')

import os
import re
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import quote
from dataclasses import dataclass
from pathlib import Path

# Cargar .env
from dotenv import load_dotenv
env_path = Path.cwd() / ".env"
if env_path.exists():
    print(f"📁 Cargando variables de entorno desde: {env_path}")
    load_dotenv(env_path, override=True)

# LangChain imports - Usando ReAct agent que es más estable
from langchain.agents import AgentType, initialize_agent, Tool
from langchain.memory import ConversationBufferMemory
from langchain.schema import Document
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_community.vectorstores import Chroma

# Google Cloud imports
from google.cloud import logging_v2

# GitHub imports
from github import Github


@dataclass
class LogQuery:
    """Estructura para queries de logs"""
    project: Optional[str] = None
    service: Optional[str] = None
    timestamp: Optional[str] = None
    severity: Optional[str] = None
    search: Optional[str] = None
    status_code: Optional[int] = None
    raw_query: str = ""


class EnhancedLogAnalyzer:
    """Agente evolucionado para análisis de logs usando LangChain"""
    
    def __init__(self, project_id: str = None):
        # Check for OpenAI API Key
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        if not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY no está configurado")
        
        print(f"🔑 Inicializando con OpenAI API Key: {self.openai_api_key[:10]}...")
        
        # Initialize LLM - Usando GPT-4 Turbo para mejor rendimiento
        self.llm = ChatOpenAI(
            model="gpt-4-turbo-preview",  # Puedes cambiar a "gpt-3.5-turbo" para menor costo
            openai_api_key=self.openai_api_key,
            temperature=0.1,
            max_tokens=4096
        )
        
        # Initialize embeddings
        self.embeddings = OpenAIEmbeddings(
            model="text-embedding-3-small",  # Modelo de embeddings más eficiente
            openai_api_key=self.openai_api_key
        )
        
        # Initialize memory con un formato más simple
        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True
        )
        
        # Initialize logging client
        self.project_id = project_id
        try:
            self.logging_client = logging_v2.Client(project=project_id) if project_id else logging_v2.Client()
            if not self.project_id:
                self.project_id = self.logging_client.project
            print(f"✅ Cliente de logging inicializado para proyecto: {self.project_id}")
        except Exception as e:
            print(f"⚠️  No se pudo inicializar el cliente de Logging: {e}")
            self.logging_client = None
        
        # GitHub client
        self.github_client = Github(os.getenv("GITHUB_TOKEN")) if os.getenv("GITHUB_TOKEN") else None
        
        # Store last filter for reference
        self.last_filter = ""

        # Store found logs entries
        self.found_logs_entries = []
        
        # Initialize tools
        self.tools = self._create_tools()
        
        # Initialize agent usando ReAct que es más estable
        self.agent = self._create_agent()

        self.clean_logs_filter = """
-protoPayload.serviceName="firestore.googleapis.com" AND
-protoPayload.serviceName="storage.googleapis.com" AND
-protoPayload.serviceName="logging.googleapis.com" AND
-httpRequest.requestUrl="/readiness_check" AND
-httpRequest.requestUrl="/liveness_check" AND
-protoPayload.methodName="google.cloud.identitytoolkit.v1.AccountManagementService.GetAccountInfo" AND
-jsonPayload.message=~"Minified React error #185" AND
-resource.labels.function_name=~"ext-f2bq" AND
-logName=~"cloudsql.googleapis.com%2Fpostgres.log" AND
-resource.labels.function_name="dopplerUsersLoader" AND
"""
        self.error_messages_list = []

        print("✅ Agente inicializado correctamente con OpenAI")
    
    def _log_event(self, message: str):
        """Log agent events"""
        print(f"[AGENT] {message}")
    
    def _parse_structured_query(self, query: str) -> LogQuery:
        """Parsea una query estructurada o semi-estructurada, incluyendo formato de filtro GCP"""
        log_query = LogQuery(raw_query=query)
        
        # # Primero verificar si es un filtro de GCP completo
        # # Patrones que indican un filtro GCP: operadores como >=, <=, =, AND, OR, etc.
        # gcp_filter_indicators = ['>=', '<=', '!=', '=~', 'AND', 'OR', 'NOT', 'resource.', 'jsonPayload.', 'protoPayload.', 'httpRequest.', 'SEARCH(']
        
        # # Si parece ser un filtro GCP completo, extraer componentes
        # if any(indicator in query for indicator in gcp_filter_indicators):
        #     # Extraer timestamp con operadores
        #     timestamp_patterns = [
        #         r'timestamp\s*([><=]+)\s*"([^"]+)"',
        #         r'timestamp\s*([><=]+)\s*\'([^\']+)\'',
        #         r'timestamp\s*([><=]+)\s*(\S+)'
        #     ]
        #     for pattern in timestamp_patterns:
        #         match = re.search(pattern, query, re.IGNORECASE)
        #         if match:
        #             operator = match.group(1)
        #             value = match.group(2)
        #             setattr(log_query, 'timestamp', f"{operator} {value}")
        #             setattr(log_query, 'timestamp_operator', operator)
        #             break
            
        #     # Extraer SEARCH
        #     search_match = re.search(r'SEARCH\s*\(\s*["\']([^"\']+)["\']\s*\)', query, re.IGNORECASE)
        #     if search_match:
        #         setattr(log_query, 'search', search_match.group(1))
            
        #     # Extraer severity
        #     severity_match = re.search(r'severity\s*=\s*["\']?(\w+)["\']?', query, re.IGNORECASE)
        #     if severity_match:
        #         setattr(log_query, 'severity', severity_match.group(1))
            
        #     # Extraer resource.type
        #     resource_type_match = re.search(r'resource\.type\s*=\s*["\']([^"\']+)["\']', query)
        #     if resource_type_match:
        #         setattr(log_query, 'resource_type', resource_type_match.group(1))
            
        #     # Extraer resource.labels.service_name
        #     service_match = re.search(r'resource\.labels\.service_name\s*=\s*["\']([^"\']+)["\']', query)
        #     if service_match:
        #         setattr(log_query, 'service', service_match.group(1))
            
        #     # Extraer cualquier otra variable con formato key=value o key="value"
        #     # Patrón general para capturar variables adicionales
        #     additional_vars = re.findall(r'(\w+(?:\.\w+)*)\s*=\s*["\']([^"\']+)["\']', query)
        #     for var_name, var_value in additional_vars:
        #         # Convertir puntos a guiones bajos para nombres de atributos válidos
        #         attr_name = var_name.replace('.', '_')
        #         if not hasattr(log_query, attr_name):
        #             setattr(log_query, attr_name, var_value)
            
        #     # Marcar que es un filtro GCP completo
        #     setattr(log_query, 'is_gcp_filter', True)
            
        # else:
            # Si no es un filtro GCP, usar el parsing original
        patterns = {
            'project': r'project:\s*([^\n,]+)',
            'service': r'service:\s*([^\n,]+)',
            'timestamp': r'timestamp:\s*([^\n,]+)',
            'severity': r'severity:\s*([^\n,]+)',
            'search': r'search:\s*([^\n,]+)',
            'status_code': r'status[_\s]?code:\s*(\d+)'
        }
        
        for field, pattern in patterns.items():
            match = re.search(pattern, query, re.IGNORECASE)
            if field == 'timestamp' and not match:
                setattr(log_query, field, 'last hour') # seteamos ultima hora como rango default
            if match:
                value = match.group(1).strip().strip('"')
                print(f"VALUE => {value}")
                if field == 'status_code':
                    value = int(value)
                setattr(log_query, field, value)
        
        setattr(log_query, 'is_gcp_filter', False)
        
        return log_query
    
    def _parse_time_period(self, period: str) -> str:
        """Convierte descripción de período a filtro de timestamp"""
        now = datetime.now(timezone.utc)
        period_lower = period.lower()
        
        # Mapeo de períodos
        time_mappings = {
            "última hora": timedelta(hours=1),
            "last hour": timedelta(hours=1),
            "últimas 2 horas": timedelta(hours=2),
            "últimas 3 horas": timedelta(hours=3),
            "últimas 24 horas": timedelta(days=1),
            "último día": timedelta(days=1),
            "última semana": timedelta(weeks=1)
        }
        
        # Buscar coincidencia directa
        for key, delta in time_mappings.items():
            if key in period_lower:
                start_time = now - delta
                return f'timestamp>="{start_time.strftime("%Y-%m-%dT%H:%M:%SZ")}"'
        
        # Buscar patrón con número de horas
        match = re.search(r'últimas?\s+(\d+)\s+horas?', period_lower)
        if match:
            hours = int(match.group(1))
            start_time = now - timedelta(hours=hours)
            return f'timestamp>="{start_time.strftime("%Y-%m-%dT%H:%M:%SZ")}"'
        
        # Siempre por default retornamos la ultima hora
        start_time = now - timedelta(hours=1)
        return f'timestamp>="{start_time.strftime("%Y-%m-%dT%H:%M:%SZ")}"'
    
    def _clean_error_message(self, message: str) -> str:
        """Limpia el mensaje de error removiendo el stack trace y formateándolo"""
        # Primero intentar con patrones específicos conocidos
        
        # Patrón para errores de Firebase/Firestore
        firebase_pattern = r'^(Error:\s*\[.*?\]\s*[^.]+\.(?:\s*FirebaseError:\s*\[.*?\]:\s*[^.]+\.)?)'
        firebase_match = re.match(firebase_pattern, message, re.DOTALL)
        if firebase_match:
            return firebase_match.group(1).strip()
        
        # Patrón para errores generales con stack trace
        error_pattern = r'^((?:Error|Warning|Exception):\s*.*?)(?:\s+at\s+\w+\s*\()'
        error_match = re.match(error_pattern, message, re.DOTALL | re.IGNORECASE)
        if error_match:
            return error_match.group(1).strip()
        
        # Buscar donde empieza el stack trace para otros casos
        stack_trace_patterns = [
            r'\s+at\s+\w+\s*\(',  # at functionName(
            r'\s+at\s+[A-Za-z]+\s*\(webpack:',  # at useMemo (webpack:
            r'\s+at\s+async\s+',  # at async
            r'\s+at\s+Object\.',  # at Object.
            r'\s+at\s+<anonymous>',  # at <anonymous>
            r'\s+at\s+module\.exports',  # at module.exports
            r'\s+at\s+process\._tickCallback',  # Node.js specific
        ]
        
        # Encontrar la posición más temprana donde empieza el stack trace
        earliest_position = len(message)
        
        for pattern in stack_trace_patterns:
            match = re.search(pattern, message)
            if match:
                earliest_position = min(earliest_position, match.start())
        
        # Extraer solo la parte antes del stack trace
        clean_message = message[:earliest_position].strip()
        
        # Limpiar saltos de línea múltiples
        clean_message = re.sub(r'\n+', ' ', clean_message)
        clean_message = re.sub(r'\s+', ' ', clean_message)
        
        # Si el mensaje queda vacío o muy corto, devolver el original limitado
        if len(clean_message) < 10:
            # Intentar extraer al menos la primera línea
            first_line = message.split('\n')[0].strip()
            if len(first_line) > 10:
                return first_line
            return message[:200] + "..." if len(message) > 200 else message
        
        return clean_message

    def _create_tools(self) -> List[Tool]:
        """Crea las herramientas para el agente"""
        tools = []
        
        # Tool 1: Generar y ejecutar consulta de logs
        def search_logs(query_description: str) -> str:
            """
            Busca logs en Google Cloud basándose en una descripción.
            Ejemplos de uso:
            - "errores del servicio uma-megalith en las últimas 3 horas"
            - "logs con severidad ERROR del servicio auth"
            - "buscar prescription errors en las últimas 2 horas"

            IMPORTANTE: Los parámetros deben estar separados por comas. Ejemplo: project: uma-development-ar, service: uma-megalith
            """
            try:
                # Parsear la query
                print(f"QUERY DESCRIPTION => {query_description}")

                # Primero verificar si es un filtro de GCP completo
                # Patrones que indican un filtro GCP: operadores como >=, <=, =, AND, OR, etc.
                gcp_filter_indicators = ['>=', '<=', '!=', '=~', 'AND', 'OR', 'NOT', 'resource.', 'jsonPayload.', 'protoPayload.', 'httpRequest.', 'SEARCH(']

                if any(indicator in query_description for indicator in gcp_filter_indicators):
                    filter_str = query_description.strip()
                    print(f"[DEBUG] Usando filtro GCP directo: {filter_str}")
                else:
                    log_query = self._parse_structured_query(query_description)
                    print(f"LOG_QUERY => {log_query}")
                    
                    # Construir el filtro
                    filter_parts = []
                    
                    # Tipo de recurso y servicio
                    if log_query.service:
                        filter_parts.append('resource.type="cloud_run_revision"')
                        filter_parts.append(f'resource.labels.service_name="{log_query.service}"')
                    
                    # Severidad
                    if log_query.severity:
                        filter_parts.append(f'severity={log_query.severity.upper()}')
                    
                    # Período de tiempo
                    if log_query.timestamp:
                        timestamp_filter = self._parse_time_period(log_query.timestamp)
                        if timestamp_filter:
                            filter_parts.append(timestamp_filter)
                    
                    # Búsqueda de texto
                    if log_query.search:
                        filter_parts.append(f'SEARCH("{log_query.search}")')
                    
                    filter_str = " AND ".join(filter_parts) if filter_parts else ""
                
                complete_filter = self.clean_logs_filter + filter_str
                self.last_filter = complete_filter
                
                print(f"[DEBUG] Filtro generado: {filter_str}")
                
                if not self.logging_client:
                    return "Error: Cliente de logging no disponible"
                
                print(f"COMPLETE FILTER => {complete_filter}")
                # Ejecutar la consulta
                entries = list(self.logging_client.list_entries(
                    filter_=complete_filter,
                    page_size=50
                ))
                
                if not entries:
                    return f"No se encontraron logs con el filtro: {filter_str}\n\nSugerencia: Verifica que el servicio y período sean correctos."
                
                # Almacenar logs encontrados
                self.found_logs_entries = entries

                # Limpiar lista de errores anterior
                self.error_messages_list = []

                # Formatear resultados mejorados
                result = f"Se encontraron {len(entries)} logs.\n\n"
                
                # Análisis detallado
                severity_count = {}
                services = set()
                error_messages = {}  # Agrupar mensajes similares
                timestamps_range = []
                unique_traces = set()
                
                for entry in entries:
                    # Timestamp range
                    timestamps_range.append(entry.timestamp)
                    
                    # Severidad
                    severity = entry.severity if hasattr(entry, 'severity') else 'UNKNOWN'
                    severity_count[severity] = severity_count.get(severity, 0) + 1
                    
                    service_name = 'unknown'

                    # Servicios
                    if hasattr(entry, "resource") and entry.resource.labels:
                        services.add(entry.resource.labels.get('service_name', 'unknown'))
                        service_name = entry.resource.labels.get("service_name", "unknown")
                    
                    # Extraer mensaje completo
                    message = ""
                    trace_id = ""
                    resource_type = entry.resource.type if hasattr(entry.resource, "type") else 'unknown'
                    
                    if hasattr(entry, "json_payload") and entry.json_payload:
                        raw_message = entry.json_payload.get("message", str(entry.json_payload))
                        # Limpiar el mensaje de stack traces
                        message = self._clean_error_message(raw_message)
                        trace_id = entry.json_payload.get("trace", "")
                        
                        # Almacenar mensajes de ERROR
                        if severity == 'ERROR' and message:
                            self.error_messages_list.append({
                                'timestamp': entry.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                                'message': message,
                                'service': service_name,
                                'resource_type': resource_type,
                                'trace': trace_id
                            })
                    elif hasattr(entry, "text_payload"):
                        message = self._clean_error_message(entry.text_payload)
                        if severity == 'ERROR' and message:
                            self.error_messages_list.append({
                                'timestamp': entry.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                                'message': message,
                                'service': service_name,
                                'resource_type': resource_type,
                                'trace': ''
                            })
                    
                    # Agrupar mensajes similares
                    if message:
                        # Normalizar mensaje para agrupación
                        message_key = re.sub(r'\b\d+\b', 'N', message[:100])  # Reemplazar números
                        message_key = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', 'UUID', message_key)  # UUIDs
                        
                        if message_key not in error_messages:
                            error_messages[message_key] = {
                                'count': 0,
                                'sample': message,
                                'severity': severity,
                                'timestamps': []
                            }
                        error_messages[message_key]['count'] += 1
                        error_messages[message_key]['timestamps'].append(entry.timestamp)
                    
                    # Traces únicos
                    if trace_id:
                        unique_traces.add(trace_id)
                
                # Construir resumen detallado
                result += "📊 **RESUMEN DETALLADO**\n\n"
                
                # Rango temporal
                if timestamps_range:
                    min_time = min(timestamps_range)
                    max_time = max(timestamps_range)
                    result += "**⏱️ Rango temporal:**\n"
                    result += f"- Desde: {min_time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                    result += f"- Hasta: {max_time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                    result += f"- Duración: {(max_time - min_time).total_seconds() / 60:.1f} minutos\n\n"
                
                # Servicios y severidades
                result += f"**🎯 Servicios afectados:** {', '.join(services)}\n"
                result += "**📈 Distribución por severidad:**\n"
                for sev, count in sorted(severity_count.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count * 100) // len(entries)
                    result += f"  - {sev}: {count} ({percentage}%)\n"
                result += "\n"
                
                # Traces únicos
                if unique_traces:
                    result += f"**🔗 Traces únicos encontrados:** {len(unique_traces)}\n\n"
                
                # Análisis de mensajes de error
                if error_messages:
                    result += "**📋 TIPOS DE MENSAJES ENCONTRADOS:**\n\n"
                    
                    # Ordenar por frecuencia
                    sorted_messages = sorted(error_messages.items(), key=lambda x: x[1]['count'], reverse=True)
                    
                    for idx, (msg_key, data) in enumerate(sorted_messages[:10], 1):  # Top 10
                        result += f"**{idx}. [{data['severity']}] Ocurrencias: {data['count']}**\n"
                        result += f"   Mensaje: {data['sample'][:200]}{'...' if len(data['sample']) > 200 else ''}\n"
                        
                        # Frecuencia temporal
                        if len(data['timestamps']) > 1:
                            time_diff = (data['timestamps'][-1] - data['timestamps'][0]).total_seconds() / 60
                            if time_diff > 0:
                                rate = data['count'] / time_diff
                                result += f"   Frecuencia: ~{rate:.1f} por minuto\n"
                        result += "\n"
                
                # Agregar lista de mensajes de ERROR al final
                if self.error_messages_list:
                    result += f"\n\n📝 **LISTA COMPLETA DE MENSAJES DE ERROR ({len(self.error_messages_list)} total):**\n\n"
                    
                    for idx, error_entry in enumerate(self.error_messages_list[:20], 1):  # Limitar a 20 para no saturar
                        result += f"**Error #{idx}**\n"
                        result += f"⏰ Timestamp: {error_entry['timestamp']}\n"
                        result += f"🎯 Servicio: {error_entry['service']}\n"
                        if error_entry['trace']:
                            result += f"🔗 Trace: {error_entry['trace']}\n"
                        result += f"💬 Mensaje: {error_entry['message']}\n"
                        result += "-" * 80 + "\n"
                    
                    if len(self.error_messages_list) > 20:
                        result += f"\n... y {len(self.error_messages_list) - 20} errores más.\n"
                    
                    # Guardar en un atributo para acceso posterior
                    result += "\n💾 Los mensajes de error han sido almacenados para análisis posterior."
                
                # Patrones detectados
                patterns = self._detect_patterns(error_messages)
                if patterns:
                    result += "**🔍 PATRONES DETECTADOS:**\n"
                    for pattern in patterns:
                        result += f"  - {pattern}\n"
                    result += "\n"
                
                result += f"🔗 Filtro usado: {filter_str}"
                
                return result
                
            except Exception as e:
                return f"Error al buscar logs: {str(e)}\n\nVerifica que tienes permisos para leer logs del proyecto."
        
        tools.append(Tool(
            name="search_logs",
            func=search_logs,
            description="Busca y analiza logs en Google Cloud. Úsala para encontrar errores, logs de servicios específicos, o logs en períodos de tiempo determinados. IMPORTANTE: Los parámetros deben estar separados por comas. Ejemplo: project: uma-development-ar, service: uma-megalith"
        ))
        
        # Tool 2: Analizar tendencias
        def analyze_log_trends(service_name: str = None, time_period: str = "últimas 24 horas") -> str:
            """
            Analiza tendencias y patrones en los logs de un servicio.
            """
            try:
                if not self.found_logs_entries:
                    return "No se encontraron logs para analizar"
                
                # Análisis de tendencias
                hour_distribution = {}
                error_types = {}
                total_errors = 0
                
                for entry in self.found_logs_entries:
                    # Distribución por hora
                    hour = entry.timestamp.hour
                    hour_distribution[hour] = hour_distribution.get(hour, 0) + 1
                    
                    # Tipos de error
                    if hasattr(entry, 'severity') and entry.severity in ['ERROR', 'CRITICAL']:
                        total_errors += 1
                        
                        message = ""
                        if hasattr(entry, "json_payload") and entry.json_payload:
                            message = entry.json_payload.get("message", "")
                        elif hasattr(entry, "text_payload"):
                            message = entry.text_payload
                        
                        # Categorizar error
                        error_type = "Otros"
                        if "timeout" in message.lower():
                            error_type = "Timeout"
                        elif "connection" in message.lower():
                            error_type = "Conexión"
                        elif "auth" in message.lower():
                            error_type = "Autenticación"
                        elif "not found" in message.lower() or "404" in message:
                            error_type = "No encontrado"
                        
                        error_types[error_type] = error_types.get(error_type, 0) + 1
                
                # Generar reporte
                result = f"📈 Análisis de tendencias - {service_name or 'Todos los servicios'}\n"
                result += f"Período: {time_period}\n"
                result += f"Total de logs analizados: {len(self.found_logs_entries)}\n"
                result += f"Total de errores: {total_errors}\n\n"
                
                if hour_distribution:
                    result += "⏰ Distribución por hora:\n"
                    for hour in sorted(hour_distribution.keys()):
                        count = hour_distribution[hour]
                        bar = "█" * (count // 5) if count > 0 else "▪"
                        result += f"  {hour:02d}:00 - {bar} ({count})\n"
                
                if error_types:
                    result += "\n🔍 Tipos de errores:\n"
                    for error_type, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
                        result += f"  - {error_type}: {count} ({count*100//total_errors}%)\n"
                
                return result
                
            except Exception as e:
                return f"Error al analizar tendencias: {str(e)}"
        
        tools.append(Tool(
            name="analyze_log_trends",
            func=analyze_log_trends,
            description="Analiza tendencias y patrones en los logs suministrados, incluyendo distribución temporal y tipos de errores."
        ))
        
        # Tool 3: Obtener mensajes de error almacenados
        def get_stored_errors(filter_keyword: str = None) -> str:
            """
            Obtiene los mensajes de error almacenados de búsquedas anteriores.
            Opcionalmente filtra por palabra clave.
            """
            if not self.error_messages_list:
                return "No hay mensajes de error almacenados. Primero debes buscar logs con search_logs."
            
            errors_to_show = self.error_messages_list
            
            if filter_keyword:
                errors_to_show = [
                    e for e in self.error_messages_list 
                    if filter_keyword.lower() in e['message'].lower()
                ]
                
                if not errors_to_show:
                    return f"No se encontraron errores que contengan '{filter_keyword}'"
            
            result = f"📝 **MENSAJES DE ERROR ALMACENADOS ({len(errors_to_show)} total):**\n\n"
            
            for idx, error_entry in enumerate(errors_to_show[:30], 1):
                result += f"**Error #{idx}**\n"
                result += f"⏰ {error_entry['timestamp']} | 🎯 {error_entry['service']}\n"
                result += f"💬 {error_entry['message']}\n"
                result += "-" * 60 + "\n"
            
            if len(errors_to_show) > 30:
                result += f"\n... y {len(errors_to_show) - 30} errores más.\n"
            
            return result
        
        tools.append(Tool(
            name="get_stored_errors",
            func=get_stored_errors,
            description="Obtiene los mensajes de error almacenados de búsquedas anteriores. Útil para revisar errores específicos o filtrar por palabras clave."
        ))
        
        return tools
    
    def _detect_patterns(self, error_messages: Dict) -> List[str]:
        """Detecta patrones comunes en los mensajes de error"""
        patterns = []
        
        # Contar keywords
        keywords_count = {
            'timeout': 0,
            'connection': 0,
            'authentication': 0,
            'permission': 0,
            'not found': 0,
            'invalid': 0,
            'failed': 0,
            'error': 0,
            'exception': 0
        }
        
        for msg_data in error_messages.values():
            msg_lower = msg_data['sample'].lower()
            for keyword in keywords_count:
                if keyword in msg_lower:
                    keywords_count[keyword] += msg_data['count']
        
        # Generar insights
        total_errors = sum(data['count'] for data in error_messages.values())
        
        for keyword, count in sorted(keywords_count.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                percentage = (count * 100) // total_errors
                if percentage > 10:  # Solo mostrar si es significativo
                    patterns.append(f"{keyword.title()} issues: {count} ({percentage}%)")
        
        # Detectar picos de errores
        all_timestamps = []
        for data in error_messages.values():
            all_timestamps.extend(data['timestamps'])
        
        if len(all_timestamps) > 10:
            all_timestamps.sort()
            # Buscar ventanas de 1 minuto con muchos errores
            window_counts = {}
            for ts in all_timestamps:
                window_key = ts.strftime('%Y-%m-%d %H:%M')
                window_counts[window_key] = window_counts.get(window_key, 0) + 1
            
            max_count = max(window_counts.values())
            avg_count = sum(window_counts.values()) / len(window_counts)
            
            if max_count > avg_count * 3:  # Pico significativo
                peak_time = [k for k, v in window_counts.items() if v == max_count][0]
                patterns.append(f"Pico de errores detectado en {peak_time} ({max_count} errores/minuto)")
        
        return patterns

    def _create_agent(self):
        """Crea el agente usando initialize_agent con configuración para OpenAI"""

        # Prompt personalizado optimizado para GPT
        prefix = """You are an expert Google Cloud logs analyzer with conversation memory.
        
        IMPORTANT: For any log analysis, you MUST:
        1. First check if you can generate a valid filter. If you cannot generate a filter due to missing information or error in the prompt, you can avoid using search_logs and analyze_log_trends tools
        2. Once you have a generated filter, first use search_logs to search for logs
        3. If you don't find logs, first try extending the analyzed time period. If you still don't find logs, don't alter other variables like severity or search, just inform the user
        4. Then use analyze_log_trends to analyze trends in the found logs
        
        This will give you a complete analysis with search and trends.

        Guidelines for building query_description:
        - Identified variables must be in the format: variable: value  Example: search: daskjdhqwwdiuoyslakdj
        - Time intervals must always be assigned to the timestamp variable. When assigning a value to timestamp, only define the start time of the period
        - If the user didn't indicate a time interval, search in the last hour by default
        - Anything you want to search in a log that doesn't have a specific field, put it in the search variable
        - If a log type is indicated (error, warning, info, etc.), assign that value to the severity variable
        
        Remember: You have conversation memory and can refer to previous analyses."""

        # Usar el agente ReAct optimizado para OpenAI
        agent = initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent=AgentType.CONVERSATIONAL_REACT_DESCRIPTION,
            memory=self.memory,
            verbose=True,
            handle_parsing_errors=True,
            max_iterations=4,
            agent_kwargs={
                "prefix": prefix,
                "input_variables": ["input", "chat_history", "agent_scratchpad"]
            }
        )
        
        return agent
    
    def _generate_logs_explorer_url(self, filter_str: str) -> str:
        """Genera URL para Google Cloud Logs Explorer"""
        if not filter_str:
            return ""
        filter_encoded = quote(filter_str, safe='')
        return f"https://console.cloud.google.com/logs/query;query={filter_encoded}?project={self.project_id}"
    
    def analyze_logs(self, query: str) -> str:
        """Método principal para analizar logs"""
        try:
            self._log_event(f"Nueva consulta recibida: {query}")
            
            # Parsear para ver si hay un proyecto específico
            log_query = self._parse_structured_query(query)
            if log_query.project and log_query.project != self.project_id:
                self.project_id = log_query.project
                try:
                    self.logging_client = logging_v2.Client(project=self.project_id)
                    print(f"✅ Cambiado al proyecto: {self.project_id}")
                except Exception as e:
                    print(f"⚠️  Error al cambiar proyecto: {e}")
            
            # Ejecutar el agente
            result = self.agent.invoke(query)
            print(f"RESULT => {result}")
            # Agregar URL de Logs Explorer si tenemos un filtro
            if self.last_filter:
                explorer_url = self._generate_logs_explorer_url(self.last_filter)
                result['output'] += f"\n\n🔗 Ver más detalles en Logs Explorer:\n{explorer_url}"
            
            self._log_event("Análisis completado")
            return result['output']
            
        except Exception as e:
            error_msg = f"Error durante el análisis: {str(e)}"
            self._log_event(error_msg)
            import traceback
            traceback.print_exc()
            return error_msg
        
    def chat_mode(self):
        """Modo de chat interactivo que mantiene la conversación"""
        print("\n💬 MODO CHAT INTERACTIVO")
        print("Escribe 'salir' o 'exit' para terminar")
        print("Escribe 'limpiar' para limpiar la memoria")
        print("-" * 60)
        
        while True:
            try:
                # Obtener input del usuario
                user_input = input("\n👤 Tu consulta: ").strip()
                
                # Comandos especiales
                if user_input.lower() in ['salir', 'exit', 'quit']:
                    print("👋 ¡Hasta luego!")
                    break
                
                if user_input.lower() == 'limpiar':
                    self.memory.clear()
                    print("🧹 Memoria limpiada")
                    continue
                
                if not user_input:
                    continue
                
                # Analizar logs
                print("\n🤖 Analizando...")
                result = self.analyze_logs(user_input)
                print(f"\n📊 Respuesta:\n{result}")
                
            except KeyboardInterrupt:
                print("\n\n👋 Chat interrumpido")
                break
            except Exception as e:
                print(f"\n❌ Error: {e}")
                import traceback
                traceback.print_exc()


def main():
    """Función principal de prueba"""
    print("\n" + "="*60)
    print("🔍 ANALIZADOR DE LOGS con OpenAI")
    print("="*60)
    
    # Crear analizador
    analyzer = EnhancedLogAnalyzer('uma-v2')
    
    # Preguntar modo
    print("\n¿Qué modo deseas usar?")
    print("1. Prueba con queries predefinidas")
    print("2. Modo chat interactivo")
    
    choice = input("\nElige (1 o 2): ").strip()
    
    if choice == "1":
        # Queries de ejemplo
        query1 = """
        project: uma-v2
        timestamp: últimas 3 horas
        search: cSyziMUPm2SUk6TG0PXJZKHdVFt2
        """
        
        print(f"\n📝 Query de prueba:\n{query1}")
        result1 = analyzer.analyze_logs(query1)
        print(f"\n📊 Resultado:\n{result1}")
        
    else:
        # Modo chat
        analyzer.chat_mode()


if __name__ == "__main__":
    main()