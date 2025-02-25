# 📌 Sistema de Autenticación con Node.js, Express, MySQL y JWT

Este es un sistema de autenticación seguro basado en **Node.js**, **Express.js**, **MySQL** y **JWT**. Incluye registro, inicio de sesión, gestión de usuarios, protección de rutas y medidas de seguridad como `helmet`, `rate-limit`, `bcryptjs`, y `sanitize-html`.

---

## 🚀 **Características**
- ✅ **Autenticación con JWT**
- ✅ **Protección contra ataques XSS y SQL Injection**
- ✅ **Registro y login con validación segura**
- ✅ **Roles de usuario (`admin`, `user`)**
- ✅ **Protección de rutas para administradores**
- ✅ **Límite de intentos de login para evitar ataques de fuerza bruta**
- ✅ **Configuración de seguridad con `helmet`**
- ✅ **Hash de contraseñas con `bcryptjs`**

---

## 🛠 **Requisitos**
Antes de ejecutar el proyecto, asegúrate de tener instalado:
- [Node.js](https://nodejs.org/)
- [MySQL](https://www.mysql.com/)
- Un editor de código como **VSCode** o **WebStorm**

---

## 📥 **Instalación**
Sigue estos pasos para instalar y configurar el proyecto en tu máquina:

### 1️⃣ **Clonar el repositorio**
```bash
git clone https://github.com/Ulises-Candelario/Login-System.git
cd Login-System 
```
---

### *Instalar dependencias*
```bash
npm install
```
---
## Configurar el archivo .env

Crea un archivo llamado .env en la raíz del proyecto y agrega lo siguiente:

---

## Configuración de variables de entorno
```bash
DB_HOST='TU HOST'
DB_USER='USUARIO'
DB_PASS='PASSWORD'  # Asegúrate de cambiar esta contraseña en producción
DB_NAME='login_system'

# Configuración del JWT (Token de Autenticación)
JWT_SECRET='7D!nG34Z@vF*9$kL+PqYr2M6#A!tB'
JWT_EXPIRATION='1h'

# Puerto del Servidor
PORT=3000

#Datos correo
EMAIL_USER = 'CORREO DESDE EL QUE SE ENVIARÁN LOS CÓDIGOS'
EMAIL_PASS = 'TU CONTRASEÑA'
```

---
## CONFIGURAR LA BASE DE DATOS
Ejecuta el siguiente query en MySQL para crear la base de datos y la tabla de usuarios:
```bash
CREATE DATABASE login_system;
USE login_system;

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    status ENUM('activo', 'inactivo') NOT NULL DEFAULT 'activo',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```
## Insertar usuario admin (La contraseña debe ser reemplazada con un hash seguro)
```bash
INSERT INTO users (username, password_hash, role, status) 
VALUES ('admin', '$2b$12$ReemplazarConHashSeguro', 'admin', 'activo');
```
---
## CAMBIAR CONTRASENA DEL ADMIN
Debido a que las contraseñas se almacenan como hashes bcrypt, no se pueden modificar directamente. Usa este comando en Node.js para generar un hash seguro:
```bash
node -e "const bcrypt = require('bcryptjs'); bcrypt.hash('admin123', 12).then(console.log);"
```
 Copia el hash generado y actualiza la base de datos con este query:
```bash
 UPDATE users SET password_hash = 'tuhash' WHERE username = 'admin';
```
---
 ## EJECUTAR EL SERVIDOR
 ```bash
 npm start
 ```
---
 ## ESTRUCTURA DEL PROYECTO
 ```bash
 📂 login-node
 ┣ 📂 public
 ┃ ┣ 📄 login.html
 ┃ ┣ 📄 register.html
 ┃ ┣ 📄 admin.html
 ┃ ┣ 📄 user.html
 ┃ ┗ 📂 js
 ┃   ┣ 📄 login.js
 ┃   ┣ 📄 register.js
 ┃   ┣ 📄 admin.js
 ┃   ┗ 📄 user.js
 ┣ 📄 server.js
 ┣ 📄 mailer.js
 ┣ 📄 db.js
 ┣ 📄 .env
 ┣ 📄 .gitignore
 ┗ 📄 package.json
```
