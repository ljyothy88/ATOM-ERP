import { getStore } from "@netlify/blobs";
import crypto from "crypto";

// IMPORTANT: set ATOM_ERP_SECRET in Netlify → Site settings → Environment variables.
// Without it, anyone who has this source code can forge login tokens.
const SECRET = process.env.ATOM_ERP_SECRET || "atom-erp-netlify-secret-key-2026-pro";

const ROLES = ["employee", "management", "admin"];
const TX_COLLECTIONS = [
  "enquiries", "supplierQuotations", "clientQuotations", "salesOrders",
  "salesInvoices", "purchaseOrders", "purchaseInvoices"
];

// Management users can view all records but cannot change them.
const MANAGEMENT_READ_ONLY = true;

const DEFAULT_USERS = {
  "bilal":      { password: "atom@123",     displayName: "Bilal Kaleel",    role: "employee",   status: "active", initials: "BK" },
  "gayathri":   { password: "gayathri@123", displayName: "Gayathri",        role: "employee",   status: "active", initials: "GA" },
  "manju":      { password: "manju@123",    displayName: "Manju",           role: "employee",   status: "active", initials: "MA" },
  "management": { password: "mgmt@123",     displayName: "Management User", role: "management", status: "active", initials: "MG" },
  "lakshmy":    { password: "lakshmy@123",  displayName: "Lakshmy",         role: "admin",      status: "active", initials: "LA" }
};

// ---------- Password hashing (scrypt). Plain-text passwords are upgraded on first successful login. ----------
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(String(pw), salt, 32).toString("hex");
  return `scrypt$${salt}$${hash}`;
}

function checkPassword(stored, given) {
  if (!stored) return false;
  if (stored.startsWith("scrypt$")) {
    const [, salt, hash] = stored.split("$");
    const test = crypto.scryptSync(String(given), salt, 32);
    const ref = Buffer.from(hash, "hex");
    return ref.length === test.length && crypto.timingSafeEqual(ref, test);
  }
  return stored === given; // legacy plain text
}

function makeInitials(name) {
  return (name || "").split(/\s+/).filter(Boolean).map(w => w[0]).join("").toUpperCase().slice(0, 2) || "U";
}

async function getUsersConfig(store) {
  try {
    let savedUsers = await store.get("erp_users", { type: "json" });
    if (!savedUsers || Object.keys(savedUsers).length === 0) {
      savedUsers = JSON.parse(JSON.stringify(DEFAULT_USERS));
      await store.setJSON("erp_users", savedUsers);
    }
    return savedUsers;
  } catch (e) {
    return JSON.parse(JSON.stringify(DEFAULT_USERS));
  }
}

function publicUser(username, u) {
  return {
    username,
    displayName: u.displayName,
    role: u.role,
    status: u.status || "active",
    initials: u.initials || makeInitials(u.displayName),
    createdAt: u.createdAt || null,
    updatedAt: u.updatedAt || null
  };
}

function publicUserList(users) {
  return Object.keys(users).sort().map(k => publicUser(k, users[k]));
}

function createToken(username, u) {
  const payload = Buffer.from(JSON.stringify({
    username,
    displayName: u.displayName,
    role: u.role,
    initials: u.initials,
    exp: Date.now() + 7 * 24 * 3600 * 1000
  })).toString("base64url");
  const sig = crypto.createHmac("sha256", SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token || !token.includes(".")) return null;
  const [payload, sig] = token.split(".");
  const expectedSig = crypto.createHmac("sha256", SECRET).update(payload).digest("base64url");
  const a = Buffer.from(sig || "");
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (data.exp < Date.now()) return null;
    return data;
  } catch (e) {
    return null;
  }
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
  });
}

function countActiveAdmins(users, excludeKey) {
  return Object.keys(users).filter(k => k !== excludeKey && users[k].role === "admin" && users[k].status === "active").length;
}

export default async (req, context) => {
  try {
    const url = new URL(req.url);
    const action = url.searchParams.get("action") || "";
    const store = getStore("atom-erp-database-v1");

    // ---------------- LOGIN ----------------
    if (req.method === "POST" && action === "login") {
      const body = await req.json().catch(() => ({}));
      const username = (body.username || "").trim().toLowerCase();
      const password = body.password || "";
      const users = await getUsersConfig(store);
      const u = users[username];

      if (u && checkPassword(u.password, password)) {
        if (u.status !== "active") {
          return jsonResponse({ ok: false, error: "This account is inactive. Please contact the System Administrator." }, 401);
        }
        if (!String(u.password).startsWith("scrypt$")) {
          u.password = hashPassword(password);
          await store.setJSON("erp_users", users);
        }
        const token = createToken(username, u);
        return jsonResponse({ ok: true, token, user: publicUser(username, u) });
      }
      return jsonResponse({ ok: false, error: "Invalid Username or Password" }, 401);
    }

    // ---------------- SESSION CHECK ----------------
    const authHeader = req.headers.get("authorization") || "";
    const token = authHeader.replace(/^Bearer\s+/i, "");
    const tokenUser = verifyToken(token);
    if (!tokenUser) return jsonResponse({ ok: false, error: "Unauthorized session" }, 401);

    // Re-read the user on every request so deactivation, deletion and role changes take effect immediately.
    const usersNow = await getUsersConfig(store);
    const live = usersNow[tokenUser.username];
    if (!live || live.status !== "active") {
      return jsonResponse({ ok: false, error: "Account inactive or removed" }, 401);
    }
    const sessionUser = publicUser(tokenUser.username, live);
    const isAdmin = sessionUser.role === "admin";
    const isMgmt = sessionUser.role === "management";

    // ---------------- WHO AM I ----------------
    if (req.method === "GET" && action === "me") {
      return jsonResponse({ ok: true, user: sessionUser });
    }

    // ---------------- CHANGE OWN PASSWORD ----------------
    if (req.method === "POST" && action === "change-password") {
      const { oldPassword, newPassword } = await req.json().catch(() => ({}));
      if (!newPassword || newPassword.length < 6) {
        return jsonResponse({ ok: false, error: "New password must be at least 6 characters." }, 400);
      }
      const uKey = sessionUser.username;
      if (!checkPassword(usersNow[uKey].password, oldPassword)) {
        return jsonResponse({ ok: false, error: "Current password is incorrect." }, 400);
      }
      usersNow[uKey].password = hashPassword(newPassword);
      usersNow[uKey].updatedAt = new Date().toISOString();
      await store.setJSON("erp_users", usersNow);
      return jsonResponse({ ok: true, message: "Password updated successfully!" });
    }

    // ---------------- EMPLOYEE LIST (for filters) ----------------
    if (req.method === "GET" && action === "employees") {
      if (!isAdmin && !isMgmt) return jsonResponse({ ok: false, error: "Forbidden" }, 403);
      const employees = publicUserList(usersNow)
        .filter(u => u.role === "employee")
        .map(u => ({ username: u.username, displayName: u.displayName, status: u.status }));
      return jsonResponse({ ok: true, employees });
    }

    // ---------------- USER MANAGEMENT (System Admin only) ----------------
    if (action === "users") {
      if (!isAdmin) return jsonResponse({ ok: false, error: "Forbidden — System Admin only" }, 403);
      const users = usersNow;

      if (req.method === "GET") {
        return jsonResponse({ ok: true, users: publicUserList(users) });
      }

      if (req.method === "POST") {
        const body = await req.json().catch(() => ({}));
        const key = (body.username || "").trim().toLowerCase();
        const isNew = !!body.isNew;
        const displayName = (body.displayName || "").trim();
        const role = body.role || "employee";
        const status = body.status === "inactive" ? "inactive" : "active";
        const password = body.password || "";

        if (!/^[a-z0-9._-]{2,32}$/.test(key)) {
          return jsonResponse({ ok: false, error: "Username must be 2–32 characters: letters, numbers, dot, dash or underscore." }, 400);
        }
        if (!displayName) return jsonResponse({ ok: false, error: "Display name is required." }, 400);
        if (!ROLES.includes(role)) return jsonResponse({ ok: false, error: "Invalid role." }, 400);
        if (isNew && users[key]) return jsonResponse({ ok: false, error: `Username "${key}" already exists.` }, 409);
        if (!isNew && !users[key]) return jsonResponse({ ok: false, error: "User not found." }, 404);
        if (isNew && password.length < 6) return jsonResponse({ ok: false, error: "Password must be at least 6 characters." }, 400);
        if (!isNew && password && password.length < 6) return jsonResponse({ ok: false, error: "Password must be at least 6 characters." }, 400);

        const dupName = Object.keys(users).find(k => k !== key && (users[k].displayName || "").toLowerCase() === displayName.toLowerCase());
        if (dupName) return jsonResponse({ ok: false, error: `Display name "${displayName}" is already used by "${dupName}". Record ownership is matched by display name, so it must be unique.` }, 409);

        if (key === sessionUser.username) {
          if (role !== "admin") return jsonResponse({ ok: false, error: "You cannot remove your own admin role." }, 400);
          if (status !== "active") return jsonResponse({ ok: false, error: "You cannot deactivate your own account." }, 400);
        }
        if (!isNew && users[key].role === "admin" && (role !== "admin" || status !== "active") && countActiveAdmins(users, key) === 0) {
          return jsonResponse({ ok: false, error: "At least one active System Admin must remain." }, 400);
        }

        const now = new Date().toISOString();
        const oldName = isNew ? null : users[key].displayName;
        users[key] = {
          ...(users[key] || {}),
          displayName,
          role,
          status,
          initials: makeInitials(displayName),
          password: password ? hashPassword(password) : users[key].password,
          createdAt: users[key]?.createdAt || now,
          updatedAt: now
        };
        await store.setJSON("erp_users", users);

        // Keep record ownership in sync when a display name changes.
        let reassigned = 0;
        if (oldName && oldName !== displayName) {
          const db = await store.get("erp_state", { type: "json" });
          if (db) {
            TX_COLLECTIONS.forEach(c => (db[c] || []).forEach(r => {
              if (r.Created_By === oldName) { r.Created_By = displayName; reassigned++; }
            }));
            await store.setJSON("erp_state", db);
          }
        }
        return jsonResponse({ ok: true, users: publicUserList(users), reassigned });
      }

      if (req.method === "DELETE") {
        const target = (url.searchParams.get("username") || "").toLowerCase();
        if (!users[target]) return jsonResponse({ ok: false, error: "User not found." }, 404);
        if (target === sessionUser.username) return jsonResponse({ ok: false, error: "You cannot delete your own account." }, 400);
        if (users[target].role === "admin" && countActiveAdmins(users, target) === 0) {
          return jsonResponse({ ok: false, error: "At least one active System Admin must remain." }, 400);
        }
        delete users[target];
        await store.setJSON("erp_users", users);
        return jsonResponse({ ok: true, users: publicUserList(users) });
      }
    }

    // ---------------- LOAD DATA ----------------
    if (req.method === "GET" && action === "load") {
      const db = await store.get("erp_state", { type: "json" });
      if (!db) return jsonResponse({ ok: true, empty: true, user: sessionUser });

      if (sessionUser.role === "employee") {
        const empName = sessionUser.displayName;
        const filterOwn = (arr) => (Array.isArray(arr) ? arr.filter(r => r.Created_By === empName) : []);
        const data = { clients: db.clients || [], suppliers: db.suppliers || [] };
        TX_COLLECTIONS.forEach(c => { data[c] = filterOwn(db[c]); });
        return jsonResponse({ ok: true, empty: false, user: sessionUser, data });
      }
      return jsonResponse({ ok: true, empty: false, user: sessionUser, data: db });
    }

    // ---------------- SAVE DATA ----------------
    if (req.method === "POST" && action === "save") {
      if (isMgmt && MANAGEMENT_READ_ONLY) {
        return jsonResponse({ ok: false, error: "Management access is view-only." }, 403);
      }
      const payload = await req.json().catch(() => ({}));
      const incoming = payload.data || {};
      const existing = await store.get("erp_state", { type: "json" });

      // Only seed when the database is genuinely empty, or when the System Admin saves.
      if (!existing || isAdmin) {
        await store.setJSON("erp_state", incoming);
        return jsonResponse({ ok: true, syncedAt: new Date().toISOString() });
      }

      // Employees: replace only their own records, never anyone else's.
      const empName = sessionUser.displayName;
      const mergeCollection = (existingArr = [], incomingArr = []) => {
        const mine = (incomingArr || []).filter(r => r.Created_By === empName);
        const others = (existingArr || []).filter(r => r.Created_By !== empName);
        return [...mine, ...others];
      };
      // Master data: employees may add or edit entries, but cannot remove them.
      const mergeMaster = (existingArr = [], incomingArr = []) => {
        const map = new Map((existingArr || []).map(r => [r.code, r]));
        (incomingArr || []).forEach(r => { if (r && r.code) map.set(r.code, r); });
        return [...map.values()];
      };

      const merged = {
        ...existing,
        clients: mergeMaster(existing.clients, incoming.clients),
        suppliers: mergeMaster(existing.suppliers, incoming.suppliers)
      };
      TX_COLLECTIONS.forEach(c => { merged[c] = mergeCollection(existing[c], incoming[c]); });

      await store.setJSON("erp_state", merged);
      return jsonResponse({ ok: true, syncedAt: new Date().toISOString() });
    }

    return jsonResponse({ ok: false, error: "Unknown action" }, 400);
  } catch (err) {
    return jsonResponse({ ok: false, error: err.message || "Server error" }, 500);
  }
};
