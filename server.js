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
        const [results] = await db.query("SELECT id, username, role, status FROM users");
        res.json(results);
    } catch (err) {
        console.error("❌ [SERVER] Error al obtener usuarios:", err);
        res.status(500).json({ error: "Error interno del servidor." });
    }
});

// 📌 **Editar usuario**
app.post("/edit-user", async (req, res) => {
    const { userId, newUsername } = req.body;
    const sanitizedUsername = sanitizeHtml(newUsername, { allowedTags: [], allowedAttributes: {} });

    try {
        await db.query("UPDATE users SET username = ? WHERE id = ?", [sanitizedUsername, userId]);
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
    console.log("📌 [SERVER] Se recibió una solicitud de login.");

    const { username, password } = req.body;

    if (!username || !password) {
        console.warn("⚠️ [SERVER] Falta usuario o contraseña.");
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    const sanitizedUsername = sanitizeHtml(username, { allowedTags: [], allowedAttributes: {} });

    try {
        const [results] = await db.query("SELECT id, password_hash, role, status FROM users WHERE username = ?", [sanitizedUsername]);

        if (results.length === 0) {
            console.warn("⚠️ [SERVER] Usuario no encontrado.");
            return res.status(401).json({ error: "Usuario o contraseña incorrectos." });
        }

        const user = results[0];

        if (user.status === "inactivo") {
            console.warn("⛔ [SERVER] Usuario inactivo.");
            return res.status(403).json({ error: "Tu cuenta está inactiva. Contacta con el administrador." });
        }

        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!isValidPassword) {
            console.warn("⚠️ [SERVER] Contraseña incorrecta.");
            return res.status(401).json({ error: "Usuario o contraseña incorrectos." });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });

        console.log("✅ [SERVER] Token generado:", token);

        res.json({ message: "Login exitoso", token, role: user.role });

    } catch (err) {
        console.error("❌ [SERVER] Error al procesar el login:", err);
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
    const { username, password } = req.body;
    const sanitizedUsername = sanitizeHtml(username, { allowedTags: [], allowedAttributes: {} });

    if (!sanitizedUsername || !password) {
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    // 🔹 Validar la seguridad de la contraseña
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
    const weakPasswords = ["admin", "password", "1234", "qwerty", "test", "abc123", "contraseña", "admin123", "123456","12345678",""];

    if (!passwordRegex.test(password) || weakPasswords.includes(password.toLowerCase())) {
        return res.status(400).json({ error: "La contraseña es demasiado débil. Usa al menos 8 caracteres con mayúsculas, minúsculas, números y símbolos." });
    }

    try {
        // 🔹 Verificar si el usuario ya existe
        const [existingUser] = await db.query("SELECT id FROM users WHERE username = ?", [sanitizedUsername]);

        if (existingUser.length > 0) {
            return res.status(400).json({ error: "El usuario ya existe." });
        }

        // 🔹 Generar el hash de la contraseña
        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(password, salt);

        // 🔹 Insertar usuario en la BD
        await db.query("INSERT INTO users (username, password_hash, role, status) VALUES (?, ?, 'user', 'activo')", [sanitizedUsername, hashedPassword]);

        res.json({ message: "Usuario registrado con éxito." });

    } catch (err) {
        console.error("❌ [SERVER] Error en el registro:", err);
        res.status(500).json({ error: "Error interno del servidor." });
    }
});

// 📌 **Iniciar Servidor**
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Servidor ejecutándose en http://localhost:${PORT}`);
});
