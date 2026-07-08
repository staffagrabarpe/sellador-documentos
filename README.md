# Sellador de Documentos

App simple para sellar documentos PDF con un código único + QR + contraseña,
y validarlos después mostrando el documento auténtico.

## Variables de entorno

- `PORT` (opcional, por defecto 3000)
- `BASE_URL` (IMPORTANTE) — la URL pública final donde quedará la app.
  Ejemplo: `https://sellos.midominio.com`
- `SESSION_SECRET` — cualquier texto largo y aleatorio, para firmar las sesiones.
- `DATA_DIR` (opcional) — carpeta donde se guardan los documentos y la base de
  datos. Por defecto `./data`. En Dokploy debe apuntar a un volumen persistente,
  ej: `/app/data`.

## Despliegue en Dokploy

Ver las instrucciones detalladas que te dio Claude en el chat.
