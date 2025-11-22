## [2025-11-21 XX:XX] - Explotación de OS Command Injection (Medium)

**URL:**  
http://192.168.56.1/vulnerabilities/exec/

**Payload utilizado:**  
127.0.0.1 | ls


**Resultado:**  
El servidor ejecutó comandos del sistema operativo y mostró archivos internos de la aplicación (`help`, `index.php`, `source`). Esto confirma la presencia de OS Command Injection en nivel Medium.

**Evidencias:**  
- Captura: `command_exploit_01.png`  
- Petición Burp: `command_injection_request.txt`

**Clasificación preliminar:**  
- OWASP: A03 – Injection  
- CWE: CWE-78  
- Severidad: CVSS 9.8 (Critical)
