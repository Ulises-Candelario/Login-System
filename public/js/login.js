console.log("Script cargado correctamente");

document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("login-btn").addEventListener("click", login);
    document.getElementById("register-btn").addEventListener("click", goToRegister);
});

function sanitizeInput(input) {
    return input.replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

console.log("Script de login.js cargado correctamente.");

async function login() {
    let username = document.getElementById("username").value.trim();
    let password = document.getElementById("password").value.trim();

    if (username === "" || password === "") {
        document.getElementById("error-message").innerText = "Todos los campos son obligatorios.";
        return;
    }

    try {

        const response = await fetch("http://localhost:3000/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        });

        const data = await response.json();

        console.log("🔹 Respuesta del servidor:", data);

        if (!response.ok) {
            console.warn("⚠️ Error al iniciar sesión:", data.error);
            document.getElementById("error-message").innerText = data.error;
            return;
        }

        console.log("✅ Login exitoso, almacenando token...");

        const expirationTime = Date.now() + 60 * 60 * 1000; // 1 hora

        localStorage.setItem("token", data.token);
        localStorage.setItem("role", data.role);
        localStorage.setItem("token_expiration", expirationTime);

        console.log("🔹 Token expira en:", new Date(expirationTime));

        // Redirigir según el rol
        if (data.role === "admin") {
            window.location.href = "admin.html";
        } else {
            window.location.href = "user.html";
        }

    } catch (error) {
        console.error("❌ Error en la solicitud de login:", error);
        document.getElementById("error-message").innerText = "No se pudo conectar con el servidor.";
    }
}

function goToRegister() {
    window.location.href = "register.html";
}
