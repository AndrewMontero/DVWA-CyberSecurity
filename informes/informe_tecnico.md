# Informe Técnico de Pentesting
## DVWA - Security Level: Medium

---

## 1. Portada

**Proyecto**: Auditoría de Seguridad - DVWA Medium  
**Equipo**: [Nombre del Equipo]  
**Integrantes**: [Persona A] y [Persona B]  
**Fecha**: [Fecha]  
**Versión**: 1.0

---

## 2. Resumen Ejecutivo Técnico

Se realizó una auditoría de seguridad sobre la aplicación DVWA configurada en nivel Medium. Durante el proceso inicial se identificó **1 vulnerabilidad crítica** de tipo SQL Injection (Blind).

### Hallazgos Principales
- **1 vulnerabilidad crítica**: SQL Injection (Blind)
- **Severidad estimada**: Critical
- **Estado**: En proceso de explotación

---

## 3. Alcance y Reglas de Engagement

### 3.1 Objetivos del Pentesting

**Objetivos Generales:**
- Identificar vulnerabilidades de seguridad en DVWA nivel Medium
- Demostrar el impacto de las vulnerabilidades encontradas
- Proporcionar recomendaciones de remediación

**Objetivos Específicos:**
- Evaluar módulos de la aplicación
- Verificar las validaciones de entrada
- Comprobar la posibilidad de explotación de vulnerabilidades

### 3.2 Alcance Técnico

**Aplicación Objetivo:**
- URL: `http://localhost/`
- Aplicación: Damn Vulnerable Web Application (DVWA)
- Nivel de Seguridad: Medium

**Módulos en Alcance:**
- SQL Injection (Blind)
- Command Injection
- File Upload
- XSS (Reflected)
- XSS (Stored)

**Credenciales Utilizadas:**
- Usuario: admin
- Password: password

### 3.3 Reglas de Engagement

**Tipo de Pentesting:** Black-box

**Técnicas Permitidas:**
- Manipulación de parámetros HTTP
- Inyección de código
- Bypass de validaciones
- Uso de herramientas de pentesting

**Técnicas Prohibidas:**
- Ataques de Denegación de Servicio (DoS)
- Destrucción de datos
- Acceso a sistemas fuera del alcance

**Ventana de Tiempo:**
- Inicio: [Fecha Inicio]
- Fin: [Fecha Fin]

---

## 4. Metodología Aplicada

### 4.1 Frameworks de Referencia

**PTES (Penetration Testing Execution Standard):**
Framework profesional de 7 fases para pentesting estructurado.

**OWASP Web Security Testing Guide v4:**
Guía técnica específica para pruebas de seguridad en aplicaciones web.

### 4.2 Fases del Pentesting Ejecutadas

1. **Pre-engagement**: Definición de alcance y reglas
2. **Intelligence Gathering**: Reconocimiento de la aplicación
3. **Threat Modeling**: Identificación de amenazas potenciales
4. **Vulnerability Analysis**: Análisis de vulnerabilidades
5. **Exploitation**: Explotación de vulnerabilidades (en proceso)
6. **Post-Exploitation**: Análisis de impacto (pendiente)
7. **Reporting**: Documentación de hallazgos

### 4.3 Herramientas Utilizadas

| Herramienta | Versión | Propósito | Fase PTES |
|-------------|---------|-----------|-----------|
| Firefox DevTools | Built-in | Inspección HTML, bypass validaciones | 2, 4 |
| Navegador Web | Latest | Testing manual | 2, 4 |

---

## 5. Reconocimiento e Inteligencia

### 5.1 Mapeo de la Aplicación

**Módulos Identificados:**
- Brute Force
- Command Injection
- CSRF
- File Inclusion
- File Upload
- SQL Injection
- SQL Injection (Blind)
- XSS (DOM, Reflected, Stored)

### 5.2 Puntos de Entrada Identificados

| ID | Tipo | Ubicación | Método HTTP | Parámetros | Autenticación |
|----|------|-----------|-------------|------------|---------------|
| EP-01 | Formulario | /sqli_blind/ | GET | id, Submit | Sí |

---

## 6. Análisis Detallado de Vulnerabilidades

### VULNERABILIDAD V-01: SQL Injection (Blind)

**Clasificación:**
- **Categoría OWASP Top 10**: A03:2021 – Injection
- **CWE**: CWE-89 (SQL Injection)
- **Severidad Estimada**: Critical

**Ubicación:**
- **Módulo**: SQL Injection (Blind)
- **URL**: `http://localhost/vulnerabilities/sqli_blind/`
- **Parámetro Vulnerable**: `id` (GET)
- **Método HTTP**: GET

**Descripción Técnica:**

La aplicación no valida adecuadamente el parámetro `id` en el servidor. Aunque implementa un dropdown en el cliente limitando valores de 1 a 5, esta restricción puede bypassearse fácilmente modificando el HTML o interceptando la petición. La aplicación proporciona respuestas diferentes basadas en TRUE/FALSE, indicando vulnerabilidad a Blind SQL Injection.

**Impacto Técnico:**

- Acceso no autorizado a la base de datos
- Extracción de información sensible mediante técnicas Blind SQLi
- Posible escalación de privilegios
- Compromiso de confidencialidad

**Prueba de Concepto (PoC):**

**Paso 1: Reconocimiento - ID Válido**
- Input: `1`
- Respuesta: "User ID exists in the database"

![Comportamiento Normal](../evidencias/screenshots/SQL_injection_blind/01_comportamiento_normal.png)

**Paso 2: Bypass de Restricción Cliente**
- Técnica: Edición HTML con DevTools (F12)
- Modificación: Cambiar `<option value="1">` a `<option value="999">`
- Input: `999`
- Respuesta: "User ID is MISSING from the database"

![Bypass DevTools](../evidencias/screenshots/SQL_injection_blind/02b_devtools_modificacion.png)

**Datos Comprometidos:**

Pendiente de extracción completa mediante técnicas de Blind SQL Injection.

**Reproducibilidad:**
- **Estado**: Siempre reproducible
- **Requisitos**: Sesión autenticada

**Recomendaciones de Remediación:**

**Solución Inmediata:**
- Implementar validación estricta en el servidor
- Permitir solo valores numéricos enteros dentro del rango permitido

**Solución Permanente:**
1. Usar **Prepared Statements** (consultas parametrizadas)
2. Implementar validación de entrada robusta en servidor
3. Aplicar principio de privilegio mínimo en la base de datos
4. Nunca confiar en validaciones del lado del cliente

---

## 7. Matriz de Vulnerabilidades

### 7.1 Resumen Consolidado

| ID | Nombre | Categoría OWASP | CWE | Severidad | Estado |
|----|--------|-----------------|-----|-----------|--------|
| V-01 | SQL Injection (Blind) | A03 | CWE-89 | Critical | Identificada |

### 7.2 Estadísticas de Vulnerabilidades

**Distribución por Severidad:**
- Críticas: 1 (100%)
- Altas: 0 (0%)
- Medias: 0 (0%)
- Bajas: 0 (0%)

**Total identificado hasta ahora**: 1

---

## 8. Conclusiones y Recomendaciones Generales

### 8.1 Conclusiones Preliminares

La aplicación DVWA en nivel Medium confía en validaciones del lado del cliente que pueden ser fácilmente bypasseadas. Se identificó vulnerabilidad crítica de SQL Injection (Blind) que requiere explotación completa para determinar alcance total del impacto.

### 8.2 Recomendaciones Estratégicas

**Priorización de Remediación:**

| Prioridad | Vulnerabilidad | Esfuerzo | Impacto | Timeline |
|-----------|----------------|----------|---------|----------|
| P0 - Crítico | SQL Injection (V-01) | Medio | Alto | Inmediato (1-7 días) |

---

## 9. Anexos

### Anexo A: Glosario de Términos

- **SQL Injection**: Técnica de inyección que explota vulnerabilidades en la capa de datos
- **Blind SQL Injection**: SQLi donde se infiere información mediante respuestas TRUE/FALSE
- **DevTools**: Herramientas de desarrollo integradas en navegadores web
- **Prepared Statement**: Consulta SQL parametrizada que previene inyecciones

### Anexo B: Evidencias

Ubicación: `/evidencias/screenshots/SQL_injection_blind/`

---

**Fin del Informe Técnico**
*Este documento se actualizará conforme avance la auditoría*