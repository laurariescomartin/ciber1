# Security Headers

Source: OWASP Secure Headers Project
Topic: HTTP security headers

## Content-Security-Policy

Content-Security-Policy (CSP) permite definir qué recursos puede cargar
un navegador para una página web.

Una política restrictiva puede ayudar a reducir el impacto de ataques
de Cross-Site Scripting (XSS) y de inyección de contenido.

La política debe adaptarse a los recursos legítimos de la aplicación.
Evita utilizar directivas excesivamente permisivas como
`default-src *` o `'unsafe-inline'` sin una justificación técnica.

Una CSP no sustituye a la validación de entradas ni a la codificación
de salida.

## Strict-Transport-Security

HTTP Strict Transport Security (HSTS) indica al navegador que debe
acceder al sitio mediante HTTPS durante un periodo determinado.

Antes de habilitar HSTS, es necesario verificar que HTTPS funciona
correctamente en el dominio y en los subdominios que se quieran incluir.

La directiva `includeSubDomains` puede afectar a subdominios que no
estén preparados para HTTPS.

## X-Content-Type-Options

El valor `nosniff` evita que el navegador interprete ciertos recursos
utilizando un tipo MIME distinto al declarado por el servidor.

Este encabezado ayuda a reducir algunos riesgos relacionados con la
interpretación incorrecta del contenido.

## X-Frame-Options

X-Frame-Options permite controlar si una página puede mostrarse dentro
de un frame.

Puede ayudar a mitigar ataques de clickjacking.

En aplicaciones modernas, también puede utilizarse la directiva
`frame-ancestors` de Content-Security-Policy.

## Referrer-Policy

Referrer-Policy controla qué información de referencia se envía
cuando el navegador navega desde una página a otra.

Una política adecuada ayuda a reducir la exposición de información
de las URL a otros sitios.