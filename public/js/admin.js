console.log("Script cargado correctamente");

document.addEventListener("DOMContentLoaded", function () {
    verificarAutenticacion();
    cargarUsuarios();
    document.getElementById("logout-btn").addEventListener("click", logout);
});

function getToken() {
    return localStorage.getItem("token");
}

function sanitizeInput(input) {
    return input.replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

async function verificarAutenticacion() {
    const token = getToken();
    if (!token) {
        window.location.href = "login.html";
    }
}

async function cargarUsuarios() {
    try {
        const response = await fetch("http://localhost:3000/users", {
            headers: { "Authorization": `Bearer ${getToken()}` }
        });

        if (!response.ok) {
            throw new Error("Error al obtener usuarios.");
        }

        const users = await response.json();
        const usersTable = document.getElementById("users");

        usersTable.innerHTML = "";
        users.forEach(user => {
            // 🔹 Evita mostrar al administrador en la lista
            if (user.role === "admin") return;

            const row = document.createElement("tr");
            row.innerHTML = `
                <td><input type="text" class="user-input" data-id="${user.id}" value="${sanitizeInput(user.username)}"></td>
                <td>${user.role}</td>
                <td>
                    <select class="status-select" data-id="${user.id}">
                        <option value="activo" ${user.status === "activo" ? "selected" : ""}>Activo</option>
                        <option value="inactivo" ${user.status === "inactivo" ? "selected" : ""}>Inactivo</option>
                    </select>
                </td>
                <td>
                    <button class="edit-btn" data-id="${user.id}">Editar</button>
                    <button class="status-btn" data-id="${user.id}">Cambiar Estado</button>
                    <button class="delete-btn" data-id="${user.id}">Eliminar</button>
                </td>
            `;
            usersTable.appendChild(row);
        });

        // Asignar eventos a los botones después de crear los elementos dinámicamente
        document.querySelectorAll(".edit-btn").forEach(btn => {
            btn.addEventListener("click", function () {
                editarUsuario(this.dataset.id);
            });
        });

        document.querySelectorAll(".status-btn").forEach(btn => {
            btn.addEventListener("click", function () {
                cambiarEstado(this.dataset.id);
            });
        });

        document.querySelectorAll(".delete-btn").forEach(btn => {
            btn.addEventListener("click", function () {
                eliminarUsuario(this.dataset.id);
            });
        });

    } catch (error) {
        document.getElementById("error-message").innerText = error.message;
    }
}

async function editarUsuario(userId) {
    const newUsername = sanitizeInput(document.querySelector(`.user-input[data-id='${userId}']`).value);
    try {
        const response = await fetch("http://localhost:3000/edit-user", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "Authorization": `Bearer ${getToken()}`
            },
            body: JSON.stringify({ userId, newUsername })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Error al editar usuario.");

        alert(data.message);
        cargarUsuarios();
    } catch (error) {
        document.getElementById("error-message").innerText = error.message;
    }
}

async function cambiarEstado(userId) {
    const status = document.querySelector(`.status-select[data-id='${userId}']`).value;
    try {
        const response = await fetch("http://localhost:3000/change-status", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "Authorization": `Bearer ${getToken()}`
            },
            body: JSON.stringify({ userId, status })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Error al cambiar estado.");

        alert(data.message);
        cargarUsuarios();
    } catch (error) {
        document.getElementById("error-message").innerText = error.message;
    }
}

async function eliminarUsuario(userId) {
    const confirmacion = confirm("¿Estás seguro de eliminar este usuario?");
    if (!confirmacion) return;

    try {
        const response = await fetch("http://localhost:3000/delete-user", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "Authorization": `Bearer ${getToken()}`
            },
            body: JSON.stringify({ userId })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Error al eliminar usuario.");

        alert(data.message);
        cargarUsuarios();
    } catch (error) {
        document.getElementById("error-message").innerText = error.message;
    }
}

function logout() {
    localStorage.removeItem("token");
    window.location.href = "login.html";
}
console.log("Script cargado correctamente");

document.addEventListener("DOMContentLoaded", function () {
    verificarAutenticacion();
    cargarUsuarios();
    document.getElementById("logout-btn").addEventListener("click", logout);
});

function getToken() {
    return localStorage.getItem("token");
}

function getRole() {
    return localStorage.getItem("role"); // Obtiene el rol del usuario
}

function sanitizeInput(input) {
    return input.replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

async function verificarAutenticacion() {
    const token = getToken();
    const role = getRole();

    if (!token || role !== "admin") {
        console.warn("⛔ Acceso denegado. Redirigiendo a login...");
        window.location.href = "login.html";
        return;
    }
}

async function cargarUsuarios() {
    try {
        const response = await fetch("http://localhost:3000/users", {
            headers: { "Authorization": `Bearer ${getToken()}` }
        });

        if (!response.ok) {
            throw new Error("Error al obtener usuarios.");
        }

        const users = await response.json();
        const usersTable = document.getElementById("users");

        usersTable.innerHTML = "";
        users.forEach(user => {
            // 🔹 Evita mostrar al administrador en la lista
            if (user.role === "admin") return;

            const row = document.createElement("tr");
            row.innerHTML = `
                <td><input type="text" class="user-input" data-id="${user.id}" value="${sanitizeInput(user.username)}"></td>
                <td>${user.role}</td>
                <td>
                    <select class="status-select" data-id="${user.id}">
                        <option value="activo" ${user.status === "activo" ? "selected" : ""}>Activo</option>
                        <option value="inactivo" ${user.status === "inactivo" ? "selected" : ""}>Inactivo</option>
                    </select>
                </td>
                <td>
                    <button class="edit-btn" data-id="${user.id}">Editar</button>
                    <button class="status-btn" data-id="${user.id}">Cambiar Estado</button>
                    <button class="delete-btn" data-id="${user.id}">Eliminar</button>
                </td>
            `;
            usersTable.appendChild(row);
        });

        // Asignar eventos a los botones después de crear los elementos dinámicamente
        document.querySelectorAll(".edit-btn").forEach(btn => {
            btn.addEventListener("click", function () {
                editarUsuario(this.dataset.id);
            });
        });

        document.querySelectorAll(".status-btn").forEach(btn => {
            btn.addEventListener("click", function () {
                cambiarEstado(this.dataset.id);
            });
        });

        document.querySelectorAll(".delete-btn").forEach(btn => {
            btn.addEventListener("click", function () {
                eliminarUsuario(this.dataset.id);
            });
        });

    } catch (error) {
        document.getElementById("error-message").innerText = error.message;
    }
}

async function editarUsuario(userId) {
    const newUsername = sanitizeInput(document.querySelector(`.user-input[data-id='${userId}']`).value);
    try {
        const response = await fetch("http://localhost:3000/edit-user", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "Authorization": `Bearer ${getToken()}`
            },
            body: JSON.stringify({ userId, newUsername })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Error al editar usuario.");

        alert(data.message);
        cargarUsuarios();
    } catch (error) {
        document.getElementById("error-message").innerText = error.message;
    }
}

async function cambiarEstado(userId) {
    const status = document.querySelector(`.status-select[data-id='${userId}']`).value;
    try {
        const response = await fetch("http://localhost:3000/change-status", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "Authorization": `Bearer ${getToken()}`
            },
            body: JSON.stringify({ userId, status })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Error al cambiar estado.");

        alert(data.message);
        cargarUsuarios();
    } catch (error) {
        document.getElementById("error-message").innerText = error.message;
    }
}

async function eliminarUsuario(userId) {
    const confirmacion = confirm("¿Estás seguro de eliminar este usuario?");
    if (!confirmacion) return;

    try {
        const response = await fetch("http://localhost:3000/delete-user", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "Authorization": `Bearer ${getToken()}`
            },
            body: JSON.stringify({ userId })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Error al eliminar usuario.");

        alert(data.message);
        cargarUsuarios();
    } catch (error) {
        document.getElementById("error-message").innerText = error.message;
    }
}

function logout() {
    localStorage.removeItem("token");
    localStorage.removeItem("role"); // Eliminamos el rol también para seguridad
    window.location.href = "login.html";
}
