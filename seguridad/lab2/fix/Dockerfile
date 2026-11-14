# Imagen de verificación del control ASVS 5.0 · 8.2.2
#
# Reemplaza únicamente la ruta compilada del carrito en la misma build de
# Juice Shop que corre en 127.0.0.1:3000, para ejecutar la prueba de regresión
# contra el comportamiento corregido sin reconstruir toda la aplicación.
#
# Uso:
#   docker build -t juice-shop-fixed:lab2 seguridad/lab2/fix
#   docker run -d --name juice-shop-fixed -p 127.0.0.1:3001:3000 juice-shop-fixed:lab2

FROM bkimminich/juice-shop:latest

COPY basket.js /juice-shop/build/routes/basket.js
