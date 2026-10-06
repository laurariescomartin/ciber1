# Cookie Security

Source: OWASP Session Management Cheat Sheet
Topic: Cookie security attributes

## Secure

El atributo Secure indica que el navegador solo debe enviar la cookie
mediante conexiones HTTPS.

Es especialmente importante para cookies que contienen identificadores
de sesión.

## HttpOnly

El atributo HttpOnly impide que JavaScript acceda directamente a la
cookie mediante las API habituales del navegador.

Ayuda a reducir el riesgo de robo de cookies mediante ciertos ataques
XSS, pero no elimina las vulnerabilidades XSS.

## SameSite

SameSite controla cuándo se envían las cookies en solicitudes
entre sitios.

Los valores más comunes son:

- Strict: restringe el envío de cookies en contextos entre sitios.
- Lax: permite determinados casos de navegación entre sitios.
- None: permite el envío entre sitios y requiere Secure en navegadores
  modernos.

La política adecuada depende del flujo de autenticación y de las
necesidades de la aplicación.

## Session Cookies

Las cookies de sesión deben configurarse teniendo en cuenta
la confidencialidad, la duración de la sesión y el riesgo de
secuestro de sesión.

Los atributos de cookie son una capa de protección y no sustituyen
a una gestión segura de sesiones en el servidor.