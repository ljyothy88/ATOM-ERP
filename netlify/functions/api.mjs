import { getStore } from "@netlify/blobs";
import crypto from "crypto";

const SECRET = process.env.ATOM_ERP_SECRET || "atom-erp-netlify-secret-key-2026-pro";

const DEFAULT_USERS = {
  "bilal":      { password: "atom@123",     displayName: "Bilal Kaleel",    role: "employee",   status: "Active", initials: "BK", email: "bilal@atom.ae" },
  "gayathri":   { password: "gayathri@123", displayName: "Gayathri",        role: "employee",   status: "Active", initials: "GA", email: "gayathri@atom.ae" },
  "manju":      { password: "manju@123",    displayName: "Manju",           role: "employee",   status: "Active", initials: "MA", email: "manju@atom.ae" },
  "management": { password: "mgmt@123",     displayName: "Management User", role: "management", status: "Active", initials: "MG", email: "management@atom.ae" },
  "lakshmy":    { password: "lakshmy@123",  displayName: "Lakshmy",         role: "admin",      status: "Active", initials: "LA", email: "lakshmy@atom.ae" }
};

async function getUsersConfig(store) {
  try {
    let savedUsers = await store.get("erp_users", { type: "json" });
    if (!savedUsers || Object.keys(savedUsers).length === 0) {
      savedUsers = { ...DEFAULT_USERS };
      await store.setJSON("erp_users", savedUsers);
    } else {
      let updated = false;
      for (const [k, v] of Object.entries(DEFAULT_USERS)) {
        if (!savedUsers[k]) {
          savedUsers[k] = v;
          updated = true;
        }
      }
      if (updated) await store.setJSON("erp_users", savedUsers);
    }
    return savedUsers;
  } catch (e) {
    return { ...DEFAULT_USERS };
  }
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
  if (sig !== expectedSig) return null;
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
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

export default async (req, context) => {
  try {
    const url = new URL(req.url);
    const action = url.searchParams.get("action") || "";
    const store = getStore("atom-erp-database-v1");

    // 1. LOGIN
    if (req.method === "POST" && action === "login") {
      const body = await req.json().catch(() => ({}));
      const username = (body.username || "").trim().toLowerCase();
      const password = body.password || "";
      const users = await getUsersConfig(store);
      const userObj = users[username];

      if (userObj) {
        const isActive = (userObj.status || "Active").toLowerCase() === "active";
        if (!isActive) {
          return jsonResponse({ ok: false, error: "Account is Inactive. Contact System Admin." }, 401);
        }
        if (userObj.password === password) {
          const token = createToken(username, userObj);
          return jsonResponse({
            ok: true,
            token,
            user: {
              username,
              displayName: userObj.displayName,
              role: userObj.role,
              initials: userObj.initials || username.slice(0, 2).toUpperCase()
            }
          });
        }
      }
      return jsonResponse({ ok: false, error: "Invalid Username or Password" }, 401);
    }

    // VERIFY TOKEN
    const authHeader = req.headers.get("authorization") || "";
    const token = authHeader.replace(/^Bearer\s+/i, "");
    const sessionUser = verifyToken(token);
    if (!sessionUser) {
      return jsonResponse({ ok: false, error: "Unauthorized session" }, 401);
    }

    // 2. CHANGE PASSWORD
    if (req.method === "POST" && action === "change-password") {
      const { oldPassword, newPassword } = await req.json();
      if (!newPassword || newPassword.length < 4) {
        return jsonResponse({ ok: false, error: "New password must be at least 4 characters." }, 400);
      }
      const users = await getUsersConfig(store);
      const uKey = sessionUser.username;
      if (!users[uKey] || users[uKey].password !== oldPassword) {
        return jsonResponse({ ok: false, error: "Current password is incorrect." }, 400);
      }
      users[uKey].password = newPassword;
      await store.setJSON("erp_users", users);
      return jsonResponse({ ok: true, message: "Password updated successfully!" });
    }

    // 3. USER MANAGEMENT (Admin Only)
    if (action === "users") {
      const users = await getUsersConfig(store);
      if (req.method === "GET") {
        if (sessionUser.role !== "admin" && sessionUser.role !== "management") {
          return jsonResponse({ ok: false, error: "Forbidden" }, 403);
        }
        return jsonResponse({ ok: true, users });
      }
      if (req.method === "POST") {
        if (sessionUser.role !== "admin") return jsonResponse({ ok: false, error: "Forbidden" }, 403);
        const { username, password, displayName, role, status, email } = await req.json();
        const key = (username || "").trim().toLowerCase();
        if (!key) return jsonResponse({ ok: false, error: "Username required" }, 400);
        const existing = users[key] || {};
        const dName = (displayName || existing.displayName || key).trim();
        const initials = dName.split(" ").filter(Boolean).map(w => w[0]).join("").toUpperCase().slice(0, 2) || key.slice(0, 2).toUpperCase();
        users[key] = {
          password: password ? password : (existing.password || "atom@123"),
          displayName: dName,
          role: role || existing.role || "employee",
          initials,
          status: status || existing.status || "Active",
          email: email !== undefined ? email : (existing.email || "")
        };
        await store.setJSON("erp_users", users);
        return jsonResponse({ ok: true, users });
      }
      if (req.method === "DELETE") {
        if (sessionUser.role !== "admin") return jsonResponse({ ok: false, error: "Forbidden" }, 403);
        const target = (url.searchParams.get("username") || "").trim().toLowerCase();
        if (target === "lakshmy") {
          return jsonResponse({ ok: false, error: "Cannot delete primary System Admin." }, 400);
        }
        if (target && users[target]) {
          delete users[target];
          await store.setJSON("erp_users", users);
        }
        return jsonResponse({ ok: true, users });
      }
    }

    // 4. LOAD DATABASE
    if (req.method === "GET" && action === "load") {
      let db = await store.get("erp_state", { type: "json" });
      const users = await getUsersConfig(store);
      if (!db) {
        return jsonResponse({ ok: true, empty: true, user: sessionUser, users });
      }
      if (sessionUser.role === "employee") {
        const empName = sessionUser.displayName;
        const filterOwn = (arr) => (Array.isArray(arr) ? arr.filter(r => r.Created_By === empName) : []);
        return jsonResponse({
          ok: true,
          empty: false,
          user: sessionUser,
          data: {
            clients: db.clients || [],
            suppliers: db.suppliers || [],
            enquiries: filterOwn(db.enquiries),
            supplierQuotations: filterOwn(db.supplierQuotations),
            clientQuotations: filterOwn(db.clientQuotations),
            salesOrders: filterOwn(db.salesOrders),
            salesInvoices: filterOwn(db.salesInvoices),
            purchaseOrders: filterOwn(db.purchaseOrders),
            purchaseInvoices: filterOwn(db.purchaseInvoices)
          }
        });
      }
      return jsonResponse({ ok: true, empty: false, user: sessionUser, users, data: db });
    }

    // 5. SAVE DATABASE
    if (req.method === "POST" && action === "save") {
      const payload = await req.json();
      const incoming = payload.data || {};
      let existing = await store.get("erp_state", { type: "json" });

      if (!existing ||
