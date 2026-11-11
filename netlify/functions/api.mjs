import { getStore } from "@netlify/blobs";
import crypto from "crypto";

const SECRET = process.env.ATOM_ERP_SECRET || "atom-erp-netlify-secret-key-2026-pro";

const DEFAULT_USERS = {
  "bilal":    { password: "atom@123",     displayName: "Bilal Kaleel", role: "employee", initials: "BK" },
  "gayathri": { password: "gayathri@123", displayName: "Gayathri",     role: "employee", initials: "GA" },
  "manju":    { password: "manju@123",    displayName: "Manju",        role: "employee", initials: "MA" },
  "lakshmy":  { password: "lakshmy@123",  displayName: "Lakshmy",      role: "admin",    initials: "LA" }
};

async function getUsersConfig(store) {
  let savedUsers = await store.get("erp_users", { type: "json" });
  if (!savedUsers) {
    savedUsers = DEFAULT_USERS;
    await store.setJSON("erp_users", savedUsers);
  }
  return savedUsers;
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

    // 1. LOGIN ENDPOINT
    if (req.method === "POST" && action === "login") {
      const { username, password } = await req.json();
      const uKey = (username || "").trim().toLowerCase();
      const users = await getUsersConfig(store);

      if (users[uKey] && users[uKey].password === password) {
        const token = createToken(uKey, users[uKey]);
        return jsonResponse({
          ok: true,
          token,
          user: {
            username: uKey,
            displayName: users[uKey].displayName,
            role: users[uKey].role,
            initials: users[uKey].initials
          }
        });
      }
      return jsonResponse({ ok: false, error: "Invalid Username or Password" }, 401);
    }

    // VERIFY TOKEN FOR PROTECTED ENDPOINTS
    const authHeader = req.headers.get("authorization") || "";
    const token = authHeader.replace(/^Bearer\s+/i, "");
    const sessionUser = verifyToken(token);
    if (!sessionUser) {
      return jsonResponse({ ok: false, error: "Unauthorized session" }, 401);
    }

    // 2. CHANGE PASSWORD ENDPOINT
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

    // 3. LOAD DATABASE ENDPOINT
    if (req.method === "GET" && action === "load") {
      let db = await store.get("erp_state", { type: "json" });
      if (!db) {
        return jsonResponse({ ok: true, empty: true, user: sessionUser });
      }
      if (sessionUser.role !== "admin") {
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
      return jsonResponse({ ok: true, empty: false, user: sessionUser, data: db });
    }

    // 4. SAVE / SYNC DATABASE ENDPOINT
    if (req.method === "POST" && action === "save") {
      const payload = await req.json();
      const incoming = payload.data || {};
      let existing = await store.get("erp_state", { type: "json" });

      if (!existing || sessionUser.role === "admin" || payload.isInitialSeed) {
        await store.setJSON("erp_state", incoming);
        return jsonResponse({ ok: true, syncedAt: new Date().toISOString() });
      }

      const empName = sessionUser.displayName;
      const mergeCollection = (existingArr = [], incomingArr = []) => {
        const others = existingArr.filter(r => r.Created_By !== empName);
        return [...incomingArr, ...others];
      };

      const merged = {
        clients: incoming.clients || existing.clients || [],
        suppliers: incoming.suppliers || existing.suppliers || [],
        enquiries: mergeCollection(existing.enquiries, incoming.enquiries),
        supplierQuotations: mergeCollection(existing.supplierQuotations, incoming.supplierQuotations),
        clientQuotations: mergeCollection(existing.clientQuotations, incoming.clientQuotations),
        salesOrders: mergeCollection(existing.salesOrders, incoming.salesOrders),
        salesInvoices: mergeCollection(existing.salesInvoices, incoming.salesInvoices),
        purchaseOrders: mergeCollection(existing.purchaseOrders, incoming.purchaseOrders),
        purchaseInvoices: mergeCollection(existing.purchaseInvoices, incoming.purchaseInvoices)
      };

      await store.setJSON("erp_state", merged);
      return jsonResponse({ ok: true, syncedAt: new Date().toISOString() });
    }

    return jsonResponse({ ok: false, error: "Unknown action" }, 400);
  } catch (err) {
    return jsonResponse({ ok: false, error: err.message || "Server error" }, 500);
  }
};
