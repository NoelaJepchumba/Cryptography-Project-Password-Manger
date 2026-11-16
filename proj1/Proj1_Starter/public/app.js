
const addForm = document.getElementById("addForm");
const getForm = document.getElementById("getForm");
const lockButton = document.getElementById("lockButton");

const addMessage = document.getElementById("addMessage");
const result = document.getElementById("result");

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

    } catch (error) {
        addMessage.textContent = error.message;
    }
});

// Retrieve a password
getForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const domain = document.getElementById("searchDomain").value.trim();

    try {
        const response = await fetch("/api/get", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Could not retrieve password.");
        }

        if (data.password === null) {
            result.textContent = "No password found for this website.";
        } else {
            result.textContent = `Password: ${data.password}`;
        }

    } catch (error) {
        result.textContent = error.message;
    }
});

// Lock the vault
lockButton.addEventListener("click", async () => {
    try {
        await fetch("/api/lock", { method: "POST" });
        window.location.href = "/";
    } catch (error) {
        alert("Could not lock the vault.");
    }
});
