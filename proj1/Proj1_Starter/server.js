
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { Keychain } = require("./password-manager");

const PORT = 3000;
const HOST = "127.0.0.1";

const publicDir = path.join(__dirname, "public");
const vaultFile = path.join(__dirname, "vault.json");

// Active login sessions are kept in server memory.
const sessions = new Map();

const mimeTypes = {
    ".html": "text/html",
    ".css": "text/css",
    ".js": "text/javascript",
    ".json": "application/json"
};

function sendJSON(res, status, data, extraHeaders = {}) {
    res.writeHead(status, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        ...extraHeaders
    });

    res.end(JSON.stringify(data));
}

function getSession(req) {
    const cookie = req.headers.cookie || "";
    const match = cookie.match(/vaultSession=([^;]+)/);

    if (!match) return null;

    return sessions.get(match[1]) || null;
}

function readJSON(req) {
    return new Promise((resolve, reject) => {
        let body = "";

        req.on("data", chunk => {
            body += chunk;

            if (body.length > 10000) {
                reject(new Error("Request is too large"));
                req.destroy();
            }
        });

        req.on("end", () => {
            try {
                resolve(JSON.parse(body || "{}"));
            } catch {
                reject(new Error("Invalid JSON"));
            }
        });

        req.on("error", reject);
    });
}

async function saveVault(keychain) {
    const [representation, checksum] = await keychain.dump();

    const savedData = JSON.stringify({
        representation,
        checksum
    });

    const temporaryFile = vaultFile + ".tmp";

    await fs.promises.writeFile(temporaryFile, savedData, "utf8");
    await fs.promises.rename(temporaryFile, vaultFile);
}

async function handleAPI(req, res, pathname) {
    try {
        // Check whether the browser is currently unlocked.
        if (req.method === "GET" && pathname === "/api/status") {
            return sendJSON(res, 200, {
                unlocked: Boolean(getSession(req))
            });
        }

        // Unlock an existing vault or create a new one.
        if (req.method === "POST" && pathname === "/api/unlock") {
            const { password } = await readJSON(req);

            if (typeof password !== "string" || password.length === 0) {
                return sendJSON(res, 400, {
                    error: "Enter your master password."
                });
            }

            let keychain;

            if (fs.existsSync(vaultFile)) {
                const saved = JSON.parse(
                    await fs.promises.readFile(vaultFile, "utf8")
                );

                keychain = await Keychain.load(
                    password,
                    saved.representation,
                    saved.checksum
                );
            } else {
                keychain = await Keychain.init(password);
                await saveVault(keychain);
            }

            const token = crypto.randomBytes(32).toString("hex");

            sessions.set(token, { keychain });

            return sendJSON(res, 200, {
                message: "Vault unlocked successfully."
            }, {
                "Set-Cookie":
                    `vaultSession=${token}; HttpOnly; SameSite=Strict; Path=/`
            });
        }

        // Lock the vault.
        if (req.method === "POST" && pathname === "/api/lock") {
            const cookie = req.headers.cookie || "";
            const match = cookie.match(/vaultSession=([^;]+)/);

            if (match) {
                sessions.delete(match[1]);
            }

            return sendJSON(res, 200, {
                message: "Vault locked."
            }, {
                "Set-Cookie":
                    "vaultSession=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
            });
        }

        // All remaining API actions require an unlocked session.
        const session = getSession(req);

        if (!session) {
            return sendJSON(res, 401, {
                error: "Your vault is locked. Please unlock it first."
            });
        }

        // Add or update a saved password.
        if (req.method === "POST" && pathname === "/api/add") {
            const { domain, password } = await readJSON(req);

            if (
                typeof domain !== "string" ||
                !domain.trim() ||
                typeof password !== "string" ||
                password.length === 0
            ) {
                return sendJSON(res, 400, {
                    error: "Enter both a website and a password."
                });
            }

            if (password.length > 64) {
                return sendJSON(res, 400, {
                    error: "Passwords must be 64 characters or fewer."
                });
            }

            await session.keychain.set(domain.trim(), password);
            await saveVault(session.keychain);

            return sendJSON(res, 200, {
                message: "Password saved successfully."
            });
        }

        // Retrieve a saved password by website.
        if (req.method === "POST" && pathname === "/api/get") {
            const { domain } = await readJSON(req);

            if (typeof domain !== "string" || !domain.trim()) {
                return sendJSON(res, 400, {
                    error: "Enter a website name."
                });
            }

            const password = await session.keychain.get(domain.trim());

            if (password === null) {
                return sendJSON(res, 404, {
                    error: "No password found for that website."
                });
            }

            return sendJSON(res, 200, { password });
        }

        // Delete a saved password.
        if (req.method === "POST" && pathname === "/api/delete") {
            const { domain } = await readJSON(req);

            if (typeof domain !== "string" || !domain.trim()) {
                return sendJSON(res, 400, {
                    error: "Enter a website name."
                });
            }

            const removed = await session.keychain.remove(domain.trim());

            if (removed) {
                await saveVault(session.keychain);
            }

            return sendJSON(res, 200, {
                message: removed
                    ? "Password deleted."
                    : "No password found for that website."
            });
        }

        return sendJSON(res, 404, {
            error: "API endpoint not found."
        });

    } catch (error) {
        console.error("API error:", error.message);

        const message =
            error.message === "Incorrect password"
                ? "Incorrect master password."
                : error.message.includes("Integrity check failed")
                    ? "Vault integrity check failed."
                    : "Something went wrong. Please try again.";

        return sendJSON(res, 400, { error: message });
    }
}

// Main HTTP server.
const server = http.createServer(async (req, res) => {
    const pathname = new URL(req.url, `http://${HOST}`).pathname;

    // Handle API requests.
    if (pathname.startsWith("/api/")) {
        return handleAPI(req, res, pathname);
    }

    if (req.method !== "GET" && req.method !== "HEAD") {
        res.writeHead(405);
        return res.end("Method not allowed");
    }

    const session = getSession(req);

    // Choose the correct page depending on login status.
    if (pathname === "/") {
        const page = session ? "index.html" : "login.html";

        res.writeHead(302, {
            Location: `/${page}`,
            "Cache-Control": "no-store"
        });

        return res.end();
    }

    // Prevent access to the dashboard while locked.
    if (pathname === "/index.html" && !session) {
        res.writeHead(302, {
            Location: "/login.html",
            "Cache-Control": "no-store"
        });

        return res.end();
    }

    // Redirect unlocked users away from the login page.
    if (pathname === "/login.html" && session) {
        res.writeHead(302, {
            Location: "/index.html",
            "Cache-Control": "no-store"
        });

        return res.end();
    }

    let requestedFile;

    try {
        requestedFile = decodeURIComponent(pathname.slice(1));
    } catch {
        res.writeHead(400);
        return res.end("Invalid URL");
    }

    const filePath = path.resolve(publicDir, requestedFile);

    // Prevent access to files outside the public folder.
    if (!filePath.startsWith(publicDir + path.sep)) {
        res.writeHead(403);
        return res.end("Forbidden");
    }

    fs.readFile(filePath, (error, content) => {
        if (error) {
            res.writeHead(404);
            return res.end("File not found");
        }

        const contentType =
            mimeTypes[path.extname(filePath)] || "application/octet-stream";

        res.writeHead(200, {
            "Content-Type": `${contentType}; charset=utf-8`,
            "Cache-Control": "no-store"
        });

        res.end(req.method === "HEAD" ? undefined : content);
    });
});

server.listen(PORT, HOST, () => {
    console.log(`Password Manager running at http://localhost:${PORT}`);
});
