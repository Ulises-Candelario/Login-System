console.log("Script cargado correctamente");

document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("register-btn").addEventListener("click", register);
    document.getElementById("login-btn").addEventListener("click", goToLogin);
});

function sanitizeInput(input) {
    return input.replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// 🔹 Función para validar contraseñas seguras
function isValidPassword(password) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
    const weakPasswords = ["admin", "password", "1234", "qwerty", "test", "abc123", "contraseña", "admin123", "123456"];

    return passwordRegex.test(password) && !weakPasswords.includes(password.toLowerCase());
}

async function register() {
    let username = document.getElementById("username").value.trim();
    let password = document.getElementById("password").value.trim();
    let email = document.getElementById("email").value.trim();

    if (username === "" || password === "" || email === "") {
        document.getElementById("error-message").innerText = "Todos los campos son obligatorios.";
        return;
    }

    // 🔹 Validar seguridad de la contraseña antes de enviar al servidor
    if (!isValidPassword(password)) {
        document.getElementById("error-message").innerText = "La contraseña debe tener al menos 8 caracteres, incluir mayúsculas, minúsculas, números y un símbolo (!@#$%^&*). No uses contraseñas débiles.";
        return;
    }

    console.log("📌 Enviando solicitud a /register con:", { username, password });

    try {
        const response = await fetch("http://localhost:3000/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username, password, email })
        });

        if (!response.ok) {
            const errorData = await response.json();
            document.getElementById("error-message").innerText = errorData.error || "Error al registrar usuario.";
            return;
        }

        const data = await response.json();
        console.log("🔹 Respuesta del servidor:", data);

        alert("Registro exitoso. Redirigiendo al login...");
        window.location.href = "login.html";
    } catch (error) {
        console.error("❌ Error en la conexión:", error);
        document.getElementById("error-message").innerText = "No se pudo conectar con el servidor.";
    }
}

function goToLogin() {
    window.location.href = "login.html";
}
