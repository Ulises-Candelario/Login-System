require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const sanitizeHtml = require("sanitize-html");
const db = require("./db");
const path = require("path");
const speakeasy = require("speakeasy");
const transporter = require("./mailer");

const app = express();
app.use(express.json());

// 🔹 **Configuración de CORS**
app.use(cors({
    origin: "http://localhost:3000",
    methods: "GET, POST, PUT, DELETE",
    allowedHeaders: "Content-Type, Authorization"
}));

// 🔹 **Protección con Helmet**
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            imgSrc: ["'self'", "data:"],
            frameAncestors: ["'none'"]
        }
    },
    frameguard: { action: "deny" },
    xssFilter: true,
    hidePoweredBy: true
}));

// 🔹 **Evitar ataques de fuerza bruta en /login**
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: "Demasiados intentos fallidos. Intenta nuevamente en 15 minutos.",
    standardHeaders: true,
    legacyHeaders: false
});
app.use("/login", loginLimiter);

// 🔹 **Servir archivos estáticos (CSS y JS)**
app.use("/js", express.static(path.join(__dirname, "js")));
app.use("/css", express.static(path.join(__dirname, "css")));
app.use(express.static(path.join(__dirname, "public")));

const JWT_SECRET = process.env.JWT_SECRET;

// 🔹 **Forzar HTTPS en producción**
app.use((req, res, next) => {
    if (req.headers["x-forwarded-proto"] !== "https" && process.env.NODE_ENV === "production") {
        return res.redirect("https://" + req.headers.host + req.url);
    }
    next();
});

// 📌 **Ruta raíz (Login)**
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

// 📌 **Obtener todos los usuarios**
app.get("/users", async (req, res) => {
    try {
        const [results] = await db.query("SELECT id, username, email, role, status FROM users");
        res.json(results);
    } catch (err) {
        console.error("❌ [SERVER] Error al obtener usuarios:", err);
        res.status(500).json({ error: "Error interno del servidor." });
    }
});

// 📌 **Editar usuario**
app.post("/edit-user", async (req, res) => {
    const { userId, newUsername, newEmail } = req.body;
    const sanitizedUsername = sanitizeHtml(newUsername, { allowedTags: [], allowedAttributes: {} });
    const sanitizedEmail = sanitizeHtml(newEmail, { allowedTags: [], allowedAttributes: {} });

    try {
        await db.query("UPDATE users SET username = ?, email = ? WHERE id = ?", [sanitizedUsername, sanitizedEmail, userId]);
        res.json({ message: "Usuario actualizado con éxito." });
    } catch (err) {
        console.error("❌ [SERVER] Error al editar usuario:", err);
        res.status(500).json({ error: "Error interno del servidor." });
    }
});

// 📌 **Eliminar usuario**
app.post("/delete-user", async (req, res) => {
    const { userId } = req.body;
    try {
        await db.query("DELETE FROM users WHERE id = ?", [userId]);
        res.json({ message: "Usuario eliminado con éxito." });
    } catch (err) {
        console.error("❌ [SERVER] Error al eliminar usuario:", err);
        res.status(500).json({ error: "Error interno del servidor." });
    }
});

// 📌 **Cambiar estado (Activo/Inactivo)**
app.post("/change-status", async (req, res) => {
    const { userId, status } = req.body;
    try {
        await db.query("UPDATE users SET status = ? WHERE id = ?", [status, userId]);
        res.json({ message: "Estado actualizado con éxito." });
    } catch (err) {
        console.error("❌ [SERVER] Error al cambiar el estado:", err);
        res.status(500).json({ error: "Error interno del servidor." });
    }
});

// 📌 **Login con seguridad**
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    const sanitizedUsername = sanitizeHtml(username, { allowedTags: [], allowedAttributes: {} });

    try {
        const [results] = await db.query("SELECT id, password_hash, role, status, email FROM users WHERE username = ?", [sanitizedUsername]);

        if (results.length === 0) {
            return res.status(401).json({ error: "Usuario o contraseña incorrectos." });
        }

        const user = results[0];

        if (user.status === "inactivo") {
            return res.status(403).json({ error: "Tu cuenta está inactiva. Contacta con el administrador." });
        }

        const isValidPassword = await bcrypt.compare(password, user.password_hash);

        if (!isValidPassword) {
            return res.status(401).json({ error: "Usuario o contraseña incorrectos." });
        }

        // Generar y enviar el código 2FA
        const secret = speakeasy.generateSecret({ length: 20 });
        const token = speakeasy.totp({
            secret: secret.base32,
            encoding: "base32"
        });

        // Guardar el secreto temporalmente (puedes usar una base de datos o caché)
        await db.query("UPDATE users SET tempSecret = ? WHERE username = ?", [secret.base32, username]);

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: "Tu código de verificación",
            text: `Tu código de verificación es: ${token}`
        });

        res.json({ message: "Código 2FA enviado. Verifica tu correo electrónico." });

    } catch (err) {
        console.error("❌ Error al procesar el login:", err);
        res.status(500).json({ error: "Error interno del servidor." });
    }
});

app.get("/verify-user", async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ error: "No autorizado." });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        const [results] = await db.query("SELECT username FROM users WHERE id = ?", [decoded.id]);

        if (results.length === 0) {
            return res.status(401).json({ error: "Usuario no encontrado." });
        }

        res.json({ username: results[0].username });

    } catch (err) {
        console.error("❌ Error en verificación de usuario:", err);
        return res.status(401).json({ error: "Token inválido o expirado." });
    }
});


// 📌 **Registro con validaciones**
app.post("/register", async (req, res) => {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    const sanitizedUsername = sanitizeHtml(username, { allowedTags: [], allowedAttributes: {} });
    const sanitizedEmail = sanitizeHtml(email, { allowedTags: [], allowedAttributes: {} });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        await db.query("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", [sanitizedUsername, hashedPassword, sanitizedEmail]);

        res.status(201).json({ message: "Usuario registrado exitosamente." });
    } catch (err) {
        console.error("❌ Error al registrar el usuario:", err);
        res.status(500).json({ error: "Error interno del servidor." });
    }
});

// Ruta para verificar el código 2FA
app.post("/verify-2fa", async (req, res) => {
    const { username, token } = req.body;

    if (!username || !token) {
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    try {
        const [results] = await db.query("SELECT id, tempSecret, role FROM users WHERE username = ?", [username]);

        if (results.length === 0) {
            return res.status(404).json({ error: "Usuario no encontrado." });
        }

        const user = results[0];
        const verified = speakeasy.totp.verify({
            secret: user.tempSecret,
            encoding: "base32",
            token,
            window: 3 // Permite una ventana de 1 intervalo de tiempo antes y después
        });

        if (!verified) {
            return res.status(400).json({ error: "Código 2FA incorrecto." });
        }

        // Eliminar el secreto temporal después de la verificación
        await db.query("UPDATE users SET tempSecret = NULL WHERE username = ?", [username]);

        // Generar el JWT
        const tokenPayload = { id: user.id, username, role: user.role };
        const jwtToken = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: "1h" });

        res.json({ message: "Código 2FA verificado.", token: jwtToken, role: user.role });
    } catch (err) {
        console.error("❌ Error al verificar el código 2FA:", err);
        res.status(500).json({ error: "Error interno del servidor." });
    }
});

// 📌 **Iniciar Servidor**
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Servidor ejecutándose en http://localhost:${PORT}`);
});
