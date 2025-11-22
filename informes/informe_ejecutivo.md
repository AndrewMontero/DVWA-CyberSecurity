# 🟧 *3. INFORME EJECUTIVO – File Upload (Medium)*  
Archivo: informes/informe_ejecutivo.md

## Vulnerabilidad #2 — Subida de archivos no segura (File Upload Bypass)

### 📝 Descripción (no técnico)
La aplicación permite que un usuario suba archivos manipulados que aparentan ser seguros (por ejemplo, imágenes), pero cuyo contenido real no es verificado.  
Esto significa que un archivo malicioso puede almacenarse dentro del servidor sin ser detectado, generando un riesgo significativo.

---

### 📌 Evidencia visual
*(Se inserta una de las capturas representativas del problema)*

![Evidencia File Upload](../evidencias/screenshots/file_upload_exploit_01.png)

---

## 📉 Riesgo para la organización

### 🔸 Integridad comprometida  
El servidor almacena archivos cuyo contenido no es confiable ni validado correctamente.

### 🔸 Riesgo de escalamiento  
Un atacante podría combinar esta vulnerabilidad con otras como **LFI, XSS o path traversal**, logrando ejecución remota o robo de información.

### 🔸 Impacto reputacional  
Un ataque exitoso podría comprometer datos internos, usuarios o afectar la disponibilidad del sistema, deteriorando la confianza de clientes y colaboradores.

---

## 🔴 Nivel de riesgo: **ALTO**

---

## 🎯 Recomendación Ejecutiva
Corregir de inmediato la validación de archivos implementando controles estrictos que impidan la carga de archivos manipulados.  
Se recomienda:

- Validar el contenido real del archivo (MIME y firma mágica).  
- Aceptar únicamente tipos permitidos mediante whitelist.  
- Almacenar los archivos en directorios **sin permisos de ejecución**.  
- Registrar y monitorear toda carga sospechosa.  

Estas medidas reducen significativamente la posibilidad de explotación o ataques encadenados dentro del sistema.
