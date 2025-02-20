console.log("📌 Script user.js cargado correctamente.");
console.log("Token enviado a verificar:", getToken());

//  Ejecutar la autenticación al cargar la página
document.addEventListener("DOMContentLoaded", function () {
    verificarAutenticacion();
    document.getElementById("logout-btn").addEventListener("click", logout);
});

function getToken() {
    return localStorage.getItem("token");
}

function getTokenExpiration() {
    return localStorage.getItem("token_expiration");
}

function logout() {
    console.log("🔹 Cierre de sesión iniciado.");
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    localStorage.removeItem("token_expiration");
    window.location.href = "login.html";
}

async function verificarAutenticacion() {
    const token = getToken();
    const expiration = getTokenExpiration();

    if (!token || !expiration) {
        console.warn("⚠️ No hay token o ha expirado, redirigiendo a login.");
        logout();
        return;
    }

    if (Date.now() > parseInt(expiration)) {
        console.warn("⏳ Token expirado, cerrando sesión.");
        logout();
        return;
    }

    try {
        console.log("📌 Verificando autenticación con token:", token);

        const response = await fetch("http://localhost:3000/verify-user", {
            method: "GET",
            headers: { "Authorization": `Bearer ${token}` }
        });

        if (!response.ok) {
            throw new Error("No autenticado.");
        }

        const data = await response.json();
        console.log("✅ Usuario autenticado:", data);

        document.getElementById("username").innerText = data.username;
    } catch (error) {
        console.error("❌ Error en autenticación:", error);
        logout();
    }
}