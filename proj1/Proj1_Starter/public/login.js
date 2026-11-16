
const loginForm = document.getElementById("loginForm");
const loginMessage = document.getElementById("loginMessage");

loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const password = document.getElementById("masterPassword").value;

    try {
        const response = await fetch("/api/unlock", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ password })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to unlock vault.");
        }

        window.location.href = "/";

    } catch (error) {
        loginMessage.textContent = error.message;
    }
});
