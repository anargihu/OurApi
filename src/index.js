const encoder = new TextEncoder();

const WEBSITE_ORIGIN = "https://ourwebsite.ndjd86d5fw.workers.dev";

function corsHeaders(origin) {
  const allowedOrigin = origin === WEBSITE_ORIGIN ? WEBSITE_ORIGIN : "null";

  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function json(data, status = 200, origin = "") {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders(origin)
    }
  });
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function toBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function hashPassword(password, salt) {
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
      iterations: 310000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return new Uint8Array(bits);
}

async function createPasswordHash(password) {
  const salt = randomBytes(16);
  const hash = await hashPassword(password, salt);

  return `${toBase64(salt)}:${toBase64(hash)}`;
}

async function verifyPassword(password, stored) {
  const [saltText, hashText] = stored.split(":");

  if (!saltText || !hashText) return false;

  const salt = fromBase64(saltText);
  const expected = fromBase64(hashText);
  const actual = await hashPassword(password, salt);

  if (actual.length !== expected.length) return false;

  let difference = 0;

  for (let i = 0; i < actual.length; i++) {
    difference |= actual[i] ^ expected[i];
  }

  return difference === 0;
}

function createId() {
  return crypto.randomUUID();
}

function getSessionId(request) {
  const authorization = request.headers.get("Authorization");

  if (!authorization?.startsWith("Bearer ")) {
    return null;
  }

  const sessionId = authorization.slice(7).trim();

  return sessionId || null;
}

async function getUser(request, env) {
  const sessionId = getSessionId(request);

  if (!sessionId) return null;

  const session = await env.DB.prepare(
    "SELECT user_id, expires_at FROM sessions WHERE id = ?"
  )
    .bind(sessionId)
    .first();

  if (!session) return null;

  if (session.expires_at <= Date.now()) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE id = ?"
    )
      .bind(sessionId)
      .run();

    return null;
  }

  return await env.DB.prepare(
    "SELECT id, username, email, created_at FROM users WHERE id = ?"
  )
    .bind(session.user_id)
    .first();
}

async function handleSignup(request, env, origin) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json({
      error: "Invalid JSON."
    }, 400, origin);
  }

  const username = String(body.username || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!username || !email || !password) {
    return json({
      error: "Username, email, and password are required."
    }, 400, origin);
  }

  if (username.length < 3 || username.length > 32) {
    return json({
      error: "Username must be between 3 and 32 characters."
    }, 400, origin);
  }

  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return json({
      error: "Username can only contain letters, numbers, and underscores."
    }, 400, origin);
  }

  if (password.length < 8) {
    return json({
      error: "Password must be at least 8 characters."
    }, 400, origin);
  }

  const existing = await env.DB.prepare(
    "SELECT id FROM users WHERE lower(username) = ? OR lower(email) = ?"
  )
    .bind(username.toLowerCase(), email)
    .first();

  if (existing) {
    return json({
      error: "Username or email is already registered."
    }, 409, origin);
  }

  const id = createId();
  const passwordHash = await createPasswordHash(password);
  const createdAt = Date.now();

  await env.DB.prepare(
    "INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(id, username, email, passwordHash, createdAt)
    .run();

  return json({
    success: true,
    user: {
      id,
      username,
      email,
      created_at: createdAt
    }
  }, 201, origin);
}

async function handleSignin(request, env, origin) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json({
      error: "Invalid JSON."
    }, 400, origin);
  }

  const login = String(body.login || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!login || !password) {
    return json({
      error: "Login and password are required."
    }, 400, origin);
  }

  const user = await env.DB.prepare(
    "SELECT id, username, email, password_hash, created_at FROM users WHERE lower(username) = ? OR lower(email) = ?"
  )
    .bind(login, login)
    .first();

  if (!user) {
    return json({
      error: "Invalid login or password."
    }, 401, origin);
  }

  const valid = await verifyPassword(password, user.password_hash);

  if (!valid) {
    return json({
      error: "Invalid login or password."
    }, 401, origin);
  }

  const sessionId = createId();
  const expiresAt = Date.now() + 1000 * 60 * 60 * 24 * 30;

  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
  )
    .bind(sessionId, user.id, expiresAt)
    .run();

  return json({
    success: true,
    token: sessionId,
    expires_at: expiresAt,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      created_at: user.created_at
    }
  }, 200, origin);
}

async function handleMe(request, env, origin) {
  const user = await getUser(request, env);

  if (!user) {
    return json({
      error: "Not signed in."
    }, 401, origin);
  }

  return json({
    signed_in: true,
    user
  }, 200, origin);
}

async function handleSignout(request, env, origin) {
  const sessionId = getSessionId(request);

  if (sessionId) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE id = ?"
    )
      .bind(sessionId)
      .run();
  }

  return json({
    success: true
  }, 200, origin);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin)
      });
    }

    const url = new URL(request.url);

    try {
      if (url.pathname === "/" && request.method === "GET") {
        return new Response("OurApi is online.", {
          headers: {
            "Content-Type": "text/plain",
            ...corsHeaders(origin)
          }
        });
      }

      if (url.pathname === "/health" && request.method === "GET") {
        return json({
          status: "online",
          service: "OurApi"
        }, 200, origin);
      }

      if (url.pathname === "/auth/signup" && request.method === "POST") {
        return await handleSignup(request, env, origin);
      }

      if (url.pathname === "/auth/signin" && request.method === "POST") {
        return await handleSignin(request, env, origin);
      }

      if (url.pathname === "/auth/me" && request.method === "GET") {
        return await handleMe(request, env, origin);
      }

      if (url.pathname === "/auth/signout" && request.method === "POST") {
        return await handleSignout(request, env, origin);
      }

      return json({
        error: "Not Found"
      }, 404, origin);
    } catch (error) {
      console.error(error);

      return json({
        error: "Internal Server Error"
      }, 500, origin);
    }
  }
};