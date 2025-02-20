require("dotenv").config();
const mysql = require("mysql2/promise");

// 📌 Configuración de la conexión con MySQL usando pool
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10, // Máximo de conexiones simultáneas
    queueLimit: 0,
    connectTimeout: 10000 // 10 segundos para evitar bloqueos por conexión lenta
};

// 📌 Habilitar SSL/TLS en producción para conexiones seguras
if (process.env.NODE_ENV === "production") {
    dbConfig.ssl = {
        rejectUnauthorized: true
    };
}

// 📌 Crear el pool de conexiones
const pool = mysql.createPool(dbConfig);

// 📌 Función para probar la conexión a la base de datos
const testConnection = async () => {
    try {
        const connection = await pool.getConnection();
        console.log("✅ Conexión exitosa a MySQL.");
        connection.release();
    } catch (err) {
        console.error("❌ Error al conectar con MySQL:", err.message);
        setTimeout(testConnection, 5000); // Intentar reconectar después de 5 segundos
    }
};

// 📌 Manejo de reconexión automática en caso de caída
pool.on("error", (err) => {
    console.error("⚠️ Error en la conexión con MySQL:", err.message);
    if (err.code === "PROTOCOL_CONNECTION_LOST") {
        console.log("🔄 Intentando reconectar...");
        testConnection();
    } else {
        throw err;
    }
});

// 📌 Probar la conexión al iniciar
testConnection();

// 📌 Exportar el pool de conexiones para usarlo en otras partes del código
module.exports = pool;
