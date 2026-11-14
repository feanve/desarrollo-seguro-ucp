# Imagen de verificación de los controles ASVS 5.0 · 8.3.1 y 2.3.2
#
# Reemplaza dos rutas compiladas sobre la misma build de Juice Shop que corre en
# 127.0.0.1:3000, para ejecutar las pruebas de regresión de los cierres
# adicionales sin reconstruir toda la aplicación.
#
# Uso:
#   docker build -t juice-shop-hardened:lab2 seguridad/lab2/cierres
#   docker run -d --name juice-shop-hardened -p 127.0.0.1:3002:3000 juice-shop-hardened:lab2

FROM bkimminich/juice-shop:latest

COPY authenticatedUsers.js /juice-shop/build/routes/authenticatedUsers.js
COPY basketItems.js /juice-shop/build/routes/basketItems.js
