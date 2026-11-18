
const addForm = document.getElementById("addForm");
const lockButton = document.getElementById("lockButton");
const addDialog = document.getElementById("addDialog");
const openAddButton = document.getElementById("openAddButton");
const closeDialogButton = document.getElementById("closeDialogButton");
const cancelAddButton = document.getElementById("cancelAddButton");
const passwordSearch = document.getElementById("passwordSearch");
const passwordList = document.getElementById("passwordList");
const passwordCount = document.getElementById("passwordCount");
const welcomeMessage = document.getElementById("welcomeMessage");
const summaryCount = document.getElementById("summaryCount");
const addMessage = document.getElementById("addMessage");
const newPasswordInput = document.getElementById("newPassword");
const toggleNewPassword = document.getElementById("toggleNewPassword");
let domains = [];

function openDialog() {
    addDialog.hidden = false;
    document.getElementById("domain").focus();
}

function closeDialog() {
    addDialog.hidden = true;
    addForm.reset();
    addMessage.textContent = "";
}

openAddButton.addEventListener("click", openDialog);
closeDialogButton.addEventListener("click", closeDialog);
cancelAddButton.addEventListener("click", closeDialog);
addDialog.addEventListener("click", (event) => {
    if (event.target === addDialog) closeDialog();
});

toggleNewPassword.addEventListener("click", () => {
    const isHidden = newPasswordInput.type === "password";
    newPasswordInput.type = isHidden ? "text" : "password";
    toggleNewPassword.textContent = isHidden ? "Hide" : "Show";
});

// Save a password
addForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const domain = document.getElementById("domain").value.trim();
    const password = document.getElementById("newPassword").value;

    try {
        const response = await fetch("/api/add", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain, password })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Could not save password.");
        }

        addMessage.textContent = data.message || "Password saved successfully!";
        addForm.reset();

        if (!domains.includes(domain)) {
            domains.push(domain);
            domains.sort((a, b) => a.localeCompare(b));
        }

        renderPasswords();
        await loadPasswords();
        setTimeout(closeDialog, 450);

    } catch (error) {
        addMessage.textContent = error.message;
    }
});

async function getPassword(domain) {
    const response = await fetch("/api/get", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not retrieve password.");
    return data.password;
}

async function deletePassword(domain) {
    if (!confirm(`Delete the password for ${domain}?`)) return;

    const response = await fetch("/api/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not delete password.");
    await loadPasswords();
}

function renderPasswords() {
    const query = passwordSearch.value.trim().toLowerCase();
    const filtered = domains.filter((domain) => domain.toLowerCase().includes(query));

    passwordCount.textContent = `${domains.length} saved`;
    summaryCount.textContent = domains.length;

    if (filtered.length === 0) {
        passwordList.innerHTML = `
            <div class="empty-state">
                <span class="empty-mark">PV</span>
                <h2>${domains.length ? "No passwords found" : "Your vault is empty"}</h2>
                <p>${domains.length ? "Try another search." : "Add your first password to get started."}</p>
                ${domains.length ? "" : '<button type="button" class="primary-button" id="emptyAddButton">Add password</button>'}
            </div>`;
        const emptyAddButton = document.getElementById("emptyAddButton");
        if (emptyAddButton) emptyAddButton.addEventListener("click", openDialog);
        return;
    }

    passwordList.innerHTML = filtered.map((domain, index) => `
        <article class="password-row">
            <div class="site-avatar" aria-hidden="true">${escapeHTML(domain.charAt(0).toUpperCase())}</div>
            <div class="site-details">
                <h2>${escapeHTML(domain)}</h2>
                <p class="password-domain">Website or app</p>
                <p class="password-value" data-domain="${escapeHTML(domain)}">••••••••••••</p>
            </div>
            <div class="row-actions">
                <button type="button" class="text-button reveal-button" data-domain="${escapeHTML(domain)}">Reveal</button>
                <button type="button" class="text-button copy-button" data-domain="${escapeHTML(domain)}">Copy</button>
                <button type="button" class="icon-button delete-button" data-domain="${escapeHTML(domain)}" aria-label="Delete ${escapeHTML(domain)}">×</button>
            </div>
        </article>`).join("");

    passwordList.querySelectorAll(".reveal-button").forEach((button) => {
        button.addEventListener("click", async () => revealPassword(button));
    });
    passwordList.querySelectorAll(".copy-button").forEach((button) => {
        button.addEventListener("click", async () => copyPassword(button));
    });
    passwordList.querySelectorAll(".delete-button").forEach((button) => {
        button.addEventListener("click", () => deletePassword(button.dataset.domain).catch(alert));
    });
}

async function revealPassword(button) {
    const row = button.closest(".password-row");
    const value = row.querySelector(".password-value");

    if (button.textContent === "Hide") {
        value.textContent = "••••••••••••";
        button.textContent = "Reveal";
        return;
    }

    try {
        value.textContent = await getPassword(button.dataset.domain);
        button.textContent = "Hide";
    } catch (error) {
        alert(error.message);
    }
}

async function copyPassword(button) {
    try {
        const password = await getPassword(button.dataset.domain);
        await navigator.clipboard.writeText(password);
        button.textContent = "Copied";
        setTimeout(() => { button.textContent = "Copy"; }, 1200);
    } catch (error) {
        alert(error.message);
    }
}

function escapeHTML(value) {
    return value.replace(/[&<"'>]/g, (character) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
    })[character]);
}

async function loadPasswords() {
    const response = await fetch("/api/list");
    if (!response.ok) {
        if (response.status === 401) window.location.href = "/login.html";
        return;
    }

    const data = await response.json();
    domains = data.domains;

    if (data.email) {
        const emailName = data.email.split("@")[0]
            .replace(/[._-]+/g, " ")
            .trim()
            .replace(/\b\w/g, (letter) => letter.toUpperCase());
        welcomeMessage.textContent = `Welcome back, ${emailName || data.email}`;
    }

    renderPasswords();
}

passwordSearch.addEventListener("input", renderPasswords);
loadPasswords();

// Lock the vault
lockButton.addEventListener("click", async () => {
    try {
        await fetch("/api/lock", { method: "POST" });
        window.location.href = "/";
    } catch (error) {
        alert("Could not lock the vault.");
    }
});
