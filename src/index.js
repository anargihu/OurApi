const WEBSITE_ORIGIN = "https://ourwebsite.ourweb.workers.dev";
const PBKDF2_ITERATIONS = 100000;

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin === WEBSITE_ORIGIN ? WEBSITE_ORIGIN : WEBSITE_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Credentials": "true"
  };
}

function json(data, status = 200, origin = WEBSITE_ORIGIN) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders(origin)
    }
  });
}

function randomId(bytes = 32) {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return [...array].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return `${PBKDF2_ITERATIONS}:${bytesToBase64(salt)}:${bytesToBase64(new Uint8Array(bits))}`;
}

async function verifyPassword(password, storedHash) {
  const parts = storedHash.split(":");

  if (parts.length !== 3) return false;

  const iterations = Number(parts[0]);
  const salt = base64ToBytes(parts[1]);
  const expected = base64ToBytes(parts[2]);

  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    },
    key,
    256
  );

  const actual = new Uint8Array(bits);

  if (actual.length !== expected.length) return false;

  let difference = 0;

  for (let i = 0; i < actual.length; i++) {
    difference |= actual[i] ^ expected[i];
  }

  return difference === 0;
}

async function getSessionUser(request, env) {
  const authorization = request.headers.get("Authorization");

  if (!authorization || !authorization.startsWith("Bearer ")) {
    return null;
  }

  const token = authorization.slice(7).trim();

  if (!token) return null;

  const session = await env.DB.prepare(
    "SELECT user_id, expires_at FROM sessions WHERE id = ?"
  ).bind(token).first();

  if (!session) return null;

  if (session.expires_at <= Date.now()) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE id = ?"
    ).bind(token).run();

    return null;
  }

  const user = await env.DB.prepare(
    "SELECT id, username, email, created_at FROM users WHERE id = ?"
  ).bind(session.user_id).first();

  return user || null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin)
      });
    }

    try {
      if (url.pathname === "/health" && request.method === "GET") {
        return json({
          status: "online",
          service: "OurApi"
        }, 200, origin);
      }

      if (url.pathname === "/db-test" && request.method === "GET") {
        const result = await env.DB.prepare(
          "SELECT COUNT(*) AS count FROM users"
        ).first();

        return json({
          database: "connected",
          users: result.count
        }, 200, origin);
      }

      if (url.pathname === "/auth/signup" && request.method === "POST") {
        const body = await request.json();

        const username = String(body.username || "").trim();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        if (!username || !email || !password) {
          return json({
            error: "Username, email, and password are required."
          }, 400, origin);
        }

        if (username.length < 3) {
          return json({
            error: "Username must be at least 3 characters."
          }, 400, origin);
        }

        if (password.length < 8) {
          return json({
            error: "Password must be at least 8 characters."
          }, 400, origin);
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM users WHERE username = ? OR email = ?"
        ).bind(username, email).first();

        if (existing) {
          return json({
            error: "Username or email is already in use."
          }, 409, origin);
        }

        const passwordHash = await hashPassword(password);
        const id = randomId(16);
        const createdAt = Date.now();

        await env.DB.prepare(
          "INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)"
        ).bind(
          id,
          username,
          email,
          passwordHash,
          createdAt
        ).run();

        return json({
          success: true,
          message: "Account created successfully."
        }, 201, origin);
      }

      if (url.pathname === "/auth/signin" && request.method === "POST") {
        const body = await request.json();

        const login = String(body.login || "").trim();
        const password = String(body.password || "");

        if (!login || !password) {
          return json({
            error: "Login and password are required."
          }, 400, origin);
        }

        const user = await env.DB.prepare(
          "SELECT id, username, email, password_hash, created_at FROM users WHERE username = ? OR email = ?"
        ).bind(login, login.toLowerCase()).first();

        if (!user) {
          return json({
            error: "Invalid username/email or password."
          }, 401, origin);
        }

        const valid = await verifyPassword(password, user.password_hash);

        if (!valid) {
          return json({
            error: "Invalid username/email or password."
          }, 401, origin);
        }

        const token = randomId(32);
        const expiresAt = Date.now() + 1000 * 60 * 60 * 24 * 30;

        await env.DB.prepare(
          "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
        ).bind(
          token,
          user.id,
          expiresAt
        ).run();

        return json({
          success: true,
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            created_at: user.created_at
          }
        }, 200, origin);
      }

      if (url.pathname === "/auth/me" && request.method === "GET") {
        const user = await getSessionUser(request, env);

        if (!user) {
          return json({
            error: "Not authenticated."
          }, 401, origin);
        }

        return json({
          user
        }, 200, origin);
      }

      if (url.pathname === "/auth/signout" && request.method === "POST") {
        const authorization = request.headers.get("Authorization");

        if (authorization && authorization.startsWith("Bearer ")) {
          const token = authorization.slice(7).trim();

          if (token) {
            await env.DB.prepare(
              "DELETE FROM sessions WHERE id = ?"
            ).bind(token).run();
          }
        }

        return json({
          success: true
        }, 200, origin);
      }

      return json({
        error: "Not Found"
      }, 404, origin);
    } catch (error) {
      console.error(error);

      return json({
        error: "Internal Server Error",
        message: error.message
      }, 500, origin);
    }
  }
};