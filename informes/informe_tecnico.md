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
