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

        if (!response.ok) {
            document.getElementById("error-message").innerText = data.error;
            return;
        }

        // Mostrar campo para ingresar el código 2FA
        document.getElementById("2fa-section").style.display = "block";
        document.getElementById("container").style.display = "none";

        document.getElementById("verify-2fa-btn").addEventListener("click", async () => {
            const token = document.getElementById("2fa-token").value.trim();

            if (token === "") {
                document.getElementById("error-message").innerText = "El código 2FA es obligatorio.";
                return;
            }

            const verifyResponse = await fetch("http://localhost:3000/verify-2fa", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, token }),
            });

            const verifyData = await verifyResponse.json();

            if (!verifyResponse.ok) {
                document.getElementById("error-message").innerText = verifyData.error;
                return;
            }

            const expirationTime = Date.now() + 60 * 60 * 1000;

            // Almacenar el JWT en localStorage
            localStorage.setItem("token", verifyData.token);
            localStorage.setItem("role", verifyData.role);
            localStorage.setItem("token_expiration", expirationTime);

            // Redirigir según el rol
            if (verifyData.role === "admin") {
                window.location.href = "admin.html";
            } else {
                window.location.href = "user.html";
            }
        });

    } catch (error) {
        document.getElementById("error-message").innerText = error;
    }
}

function goToRegister() {
    window.location.href = "register.html";
}
