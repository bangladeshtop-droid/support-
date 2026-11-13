const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const Busboy = require("busboy");
const admin = require("firebase-admin");

const PORT = process.env.PORT || 3000;
const MAIN_ADMIN_TELEGRAM_ID = "8016259396";
const DATABASE_URL = process.env.FIREBASE_DATABASE_URL || "https://goaltube-bd-default-rtdb.firebaseio.com";
const TELEGRAM_BOT_TOKEN = (process.env.TELEGRAM_BOT_TOKEN || "").trim();
const TELEGRAM_STORAGE_CHAT_ID = (process.env.TELEGRAM_STORAGE_CHAT_ID || MAIN_ADMIN_TELEGRAM_ID).trim();

const MAX_FILE_SIZE = 20 * 1024 * 1024;
const ALLOWED_EXTENSIONS = new Set([
  "jpg", "jpeg", "png", "webp", "mp4", "pdf", "zip", "rar",
  "mp3", "ogg", "wav", "m4a", "webm", "doc", "docx", "txt"
]);

let firebaseReady = false;
let firebaseInitError = null;
let db = null;

function parseServiceAccount(raw) {
  if (!raw) return null;
  const trimmed = raw.trim();
  const jsonStr = trimmed.startsWith("{")
    ? trimmed
    : Buffer.from(trimmed, "base64").toString("utf8");
  const parsed = JSON.parse(jsonStr);
  if (parsed.private_key && typeof parsed.private_key === "string") {
    parsed.private_key = parsed.private_key.replace(/\\n/g, "\n");
  }
  return parsed;
}

try {
  const serviceAccount = parseServiceAccount(process.env.FIREBASE_SERVICE_ACCOUNT);
  if (!serviceAccount) {
    throw new Error("FIREBASE_SERVICE_ACCOUNT environment variable is not set");
  }
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: DATABASE_URL
    });
  }
  db = admin.database();
  firebaseReady = true;
} catch (err) {
  firebaseInitError = err.message;
  console.error("Firebase Admin Init Error:", err.message);
}

function verifyTelegramInitData(initData, botToken) {
  if (!initData || !botToken) {
    throw new Error("Missing Telegram initData or TELEGRAM_BOT_TOKEN");
  }
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash || !/^[a-f0-9]{64}$/i.test(hash)) {
    throw new Error("Invalid Telegram signature format");
  }

  const entries = [];
  for (const [k, v] of params.entries()) {
    if (k !== "hash") entries.push([k, v]);
  }
  entries.sort((a, b) => a[0].localeCompare(b[0]));
  const dataCheckString = entries.map(([k, v]) => `${k}=${v}`).join("\n");

  const secretKey = crypto.createHmac("sha256", "WebAppData").update(botToken).digest();
  const expectedHash = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");

  const hashBuf = Buffer.from(hash, "hex");
  const expectedBuf = Buffer.from(expectedHash, "hex");
  if (hashBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(hashBuf, expectedBuf)) {
    throw new Error("Telegram signature verification failed (check TELEGRAM_BOT_TOKEN)");
  }

  const authDate = Number(params.get("auth_date"));
  const nowSec = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(authDate) || nowSec - authDate > 86400 || authDate - nowSec > 300) {
    throw new Error("Telegram session expired. Please close and reopen the Mini App.");
  }

  const userJson = params.get("user");
  if (!userJson) throw new Error("Telegram user payload missing");
  const tgUser = JSON.parse(userJson);
  if (!tgUser || !tgUser.id) throw new Error("Invalid Telegram user identity");
  return tgUser;
}

function requireConfigReady(req, res, next) {
  if (!firebaseReady || !db) {
    return res.status(500).json({ error: `Backend Firebase configuration error: ${firebaseInitError}` });
  }
  if (!TELEGRAM_BOT_TOKEN) {
    return res.status(500).json({ error: "TELEGRAM_BOT_TOKEN environment variable is missing on server" });
  }
  return next();
}

async function requireFirebaseAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (!match) return res.status(401).json({ error: "Missing authorization token" });
    req.authUser = await admin.auth().verifyIdToken(match[1]);
    return next();
  } catch (_) {
    return res.status(401).json({ error: "Invalid or expired authentication token" });
  }
}

async function requireMainAdmin(req, res, next) {
  if (!req.authUser || req.authUser.uid !== MAIN_ADMIN_TELEGRAM_ID || req.authUser.isAdmin !== true) {
    return res.status(403).json({ error: "Unauthorized Access: Admin privileges required" });
  }
  const adminSnap = await db.ref(`supportChat/admins/${MAIN_ADMIN_TELEGRAM_ID}`).get();
  if (!adminSnap.exists()) {
    return res.status(403).json({ error: "Unauthorized Access" });
  }
  return next();
}

async function sendFirstContactWelcomeIfEligible(userId) {
  if (!userId || userId === MAIN_ADMIN_TELEGRAM_ID) return false;
  const settingsSnap = await db.ref("supportChat/settings").get();
  const settings = settingsSnap.val() || {};
  if (settings.welcomeEnabled === false) return false;

  const welcomeText = (settings.welcomeMessage || "").trim();
  if (!welcomeText) return false;

  const welcomeFlagRef = db.ref(`supportChat/conversations/${userId}/welcomeSent`);
  const tx = await welcomeFlagRef.transaction((current) => {
    if (current === true || current === "processing") return;
    return "processing";
  });
  if (!tx.committed) return false;

  try {
    const now = admin.database.ServerValue.TIMESTAMP;
    const msgRef = db.ref(`supportChat/messages/${userId}`).push();
    const updates = {};
    updates[`supportChat/messages/${userId}/${msgRef.key}`] = {
      senderId: MAIN_ADMIN_TELEGRAM_ID,
      senderRole: "admin",
      type: "text",
      text: welcomeText,
      isAutoWelcome: true,
      createdAt: now,
      deleted: false
    };
    updates[`supportChat/conversations/${userId}/welcomeSent`] = true;
    updates[`supportChat/conversations/${userId}/lastMessageText`] = welcomeText;
    updates[`supportChat/conversations/${userId}/lastMessageAt`] = now;
    updates[`supportChat/conversations/${userId}/lastSenderRole`] = "admin";
    updates[`supportChat/conversations/${userId}/unreadByUser`] = 1;
    await db.ref().update(updates);
    return true;
  } catch (err) {
    await welcomeFlagRef.set(null).catch(() => {});
    throw err;
  }
}

async function uploadBufferToTelegram(buffer, fileName, mimeType) {
  const form = new FormData();
  form.append("chat_id", String(TELEGRAM_STORAGE_CHAT_ID));
  const blob = new Blob([buffer], { type: mimeType || "application/octet-stream" });

  let endpoint = "sendDocument";
  let fieldName = "document";
  const lowerMime = (mimeType || "").toLowerCase();
  const ext = (fileName.split(".").pop() || "").toLowerCase();

  if (lowerMime.startsWith("image/") && ["jpg", "jpeg", "png"].includes(ext)) {
    endpoint = "sendPhoto";
    fieldName = "photo";
  } else if (lowerMime === "video/mp4" || ext === "mp4") {
    endpoint = "sendVideo";
    fieldName = "video";
  } else if (lowerMime.startsWith("audio/") || ["mp3", "ogg", "m4a"].includes(ext)) {
    endpoint = "sendAudio";
    fieldName = "audio";
  }

  form.append(fieldName, blob, fileName || "attachment");
  form.append("disable_notification", "true");

  const tgRes = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/${endpoint}`, {
    method: "POST",
    body: form
  });
  let tgJson = await tgRes.json();

  if (!tgJson.ok && endpoint !== "sendDocument") {
    const fbForm = new FormData();
    fbForm.append("chat_id", String(TELEGRAM_STORAGE_CHAT_ID));
    fbForm.append("document", blob, fileName || "attachment");
    fbForm.append("disable_notification", "true");
    const fbRes = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument`, {
      method: "POST",
      body: fbForm
    });
    tgJson = await fbRes.json();
    endpoint = "sendDocument";
  }

  if (!tgJson.ok) {
    const desc = tgJson.description || "Telegram Bot API upload failed";
    if (/chat not found|bot was blocked|Forbidden/i.test(desc)) {
      throw new Error(
        `Bot cannot send files to storage chat (${TELEGRAM_STORAGE_CHAT_ID}). Open your bot in Telegram and send /start once.`
      );
    }
    throw new Error(desc);
  }

  const r = tgJson.result;
  let fileId = null;
  if (Array.isArray(r.photo) && r.photo.length > 0) fileId = r.photo[r.photo.length - 1].file_id;
  else if (r.video) fileId = r.video.file_id;
  else if (r.audio) fileId = r.audio.file_id;
  else if (r.voice) fileId = r.voice.file_id;
  else if (r.document) fileId = r.document.file_id;

  if (!fileId) throw new Error("Telegram did not return a file_id");
  return { fileId, telegramMethod: endpoint };
}

async function sendTelegramMessageToUser(chatId, text, fileObj = null) {
  if (!fileObj) {
    const res = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: String(chatId), text })
    });
    return res.json();
  }
  const method = fileObj.type === "image" ? "sendPhoto" : fileObj.type === "video" ? "sendVideo" : "sendDocument";
  const field = fileObj.type === "image" ? "photo" : fileObj.type === "video" ? "video" : "document";
  const payload = { chat_id: String(chatId), [field]: fileObj.fileId };
  if (text) payload.caption = text;
  const res = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  return res.json();
}

function parseMultipartUpload(req) {
  return new Promise((resolve, reject) => {
    const busboy = Busboy({ headers: req.headers, limits: { fileSize: MAX_FILE_SIZE, files: 1 } });
    const fields = {};
    let fileData = null;
    let limitHit = false;

    busboy.on("field", (name, val) => { fields[name] = val; });
    busboy.on("file", (name, stream, info) => {
      const chunks = [];
      stream.on("limit", () => { limitHit = true; });
      stream.on("data", (chunk) => chunks.push(chunk));
      stream.on("end", () => {
        fileData = {
          fileName: info.filename || "attachment",
          mimeType: info.mimeType || "application/octet-stream",
          buffer: Buffer.concat(chunks)
        };
      });
    });
    busboy.on("error", reject);
    busboy.on("finish", () => {
      if (limitHit) return reject(new Error("File exceeds the 20 MB upload limit"));
      resolve({ fields, file: fileData });
    });

    if (req.rawBody) busboy.end(req.rawBody);
    else req.pipe(busboy);
  });
}

const app = express();
app.use(cors({ origin: true, allowedHeaders: ["Content-Type", "Authorization"] }));
app.options("*", cors());

const apiRouter = express.Router();
apiRouter.use(express.json({ limit: "2mb" }));

apiRouter.get("/health", (req, res) => {
  res.json({
    ok: firebaseReady && Boolean(TELEGRAM_BOT_TOKEN),
    firebaseReady,
    firebaseInitError,
    botTokenConfigured: Boolean(TELEGRAM_BOT_TOKEN),
    adminId: MAIN_ADMIN_TELEGRAM_ID
  });
});

apiRouter.use(requireConfigReady);

apiRouter.post("/auth/telegram", async (req, res) => {
  try {
    const tgUser = verifyTelegramInitData(req.body?.initData, TELEGRAM_BOT_TOKEN);
    const uid = String(tgUser.id);
    const isAdmin = uid === MAIN_ADMIN_TELEGRAM_ID;

    const now = Date.now();
    const fullName = [tgUser.first_name, tgUser.last_name].filter(Boolean).join(" ").trim();
    const baseProfile = {
      telegramId: uid,
      firstName: tgUser.first_name || "",
      lastName: tgUser.last_name || "",
      fullName: fullName || (isAdmin ? "Admin" : `User ${uid}`),
      username: tgUser.username || "",
      photoUrl: tgUser.photo_url || "",
      lastActive: now
    };

    if (isAdmin) {
      const adminRef = db.ref(`supportChat/admins/${uid}`);
      const existing = (await adminRef.get()).val() || {};
      const adminRecord = {
        ...existing,
        ...baseProfile,
        role: "Main Admin",
        accountStatus: "active",
        createdAt: existing.createdAt || now
      };
      await adminRef.set(adminRecord);
      const customToken = await admin.auth().createCustomToken(uid, { isAdmin: true, telegramId: uid });
      return res.json({ customToken, isAdmin: true, profile: adminRecord });
    }

    const userRef = db.ref(`supportChat/users/${uid}`);
    const existing = (await userRef.get()).val() || {};
    const isBlocked = (await db.ref(`supportChat/blockedUsers/${uid}/blocked`).get()).val() === true;
    const userRecord = {
      ...existing,
      ...baseProfile,
      accountStatus: isBlocked ? "blocked" : "active",
      createdAt: existing.createdAt || now
    };
    await userRef.set(userRecord);
    const customToken = await admin.auth().createCustomToken(uid, { isAdmin: false, telegramId: uid });
    return res.json({ customToken, isAdmin: false, profile: userRecord });
  } catch (err) {
    return res.status(401).json({ error: err.message || "Authentication failed" });
  }
});

apiRouter.post("/chat/welcome", requireFirebaseAuth, async (req, res) => {
  try {
    const uid = req.authUser.uid;
    if (uid === MAIN_ADMIN_TELEGRAM_ID) return res.json({ ok: true, sent: false });
    const isBlocked = (await db.ref(`supportChat/blockedUsers/${uid}/blocked`).get()).val() === true;
    if (isBlocked) return res.status(403).json({ error: "Account is blocked" });
    const sent = await sendFirstContactWelcomeIfEligible(uid);
    return res.json({ ok: true, sent });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

apiRouter.post("/files/upload", requireFirebaseAuth, async (req, res) => {
  try {
    const { fields, file } = await parseMultipartUpload(req);
    if (!file || !file.buffer?.length) return res.status(400).json({ error: "No file uploaded" });

    const uid = req.authUser.uid;
    const isAdmin = uid === MAIN_ADMIN_TELEGRAM_ID && req.authUser.isAdmin === true;
    const chatUserId = String(fields.chatUserId || uid);

    if (!isAdmin && chatUserId !== uid) return res.status(403).json({ error: "Unauthorized" });
    if (!isAdmin) {
      const isBlocked = (await db.ref(`supportChat/blockedUsers/${uid}/blocked`).get()).val() === true;
      if (isBlocked) return res.status(403).json({ error: "Blocked users cannot upload files" });
    }

    const ext = (file.fileName.split(".").pop() || "").toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext)) return res.status(400).json({ error: `Unsupported file (.${ext})` });

    const uploaded = await uploadBufferToTelegram(file.buffer, file.fileName, file.mimeType);
    return res.json({
      ok: true,
      fileId: uploaded.fileId,
      telegramMethod: uploaded.telegramMethod,
      fileName: file.fileName,
      mimeType: file.mimeType,
      fileSize: file.buffer.length
    });
  } catch (err) {
    return res.status(400).json({ error: err.message || "Upload failed" });
  }
});

apiRouter.get("/files/get", requireFirebaseAuth, async (req, res) => {
  try {
    const fileId = String(req.query.fileId || "");
    const chatUserId = String(req.query.chatUserId || "");
    const msgId = String(req.query.msgId || "");
    if (!fileId || !chatUserId || !msgId) return res.status(400).json({ error: "Missing parameters" });

    const uid = req.authUser.uid;
    const isAdmin = uid === MAIN_ADMIN_TELEGRAM_ID && req.authUser.isAdmin === true;
    if (!isAdmin && uid !== chatUserId) return res.status(403).json({ error: "Unauthorized" });

    const msg = (await db.ref(`supportChat/messages/${chatUserId}/${msgId}`).get()).val();
    if (!msg || msg.deleted || msg.fileId !== fileId) return res.status(404).json({ error: "File not found" });

    const tgInfoRes = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getFile?file_id=${encodeURIComponent(fileId)}`);
    const tgInfo = await tgInfoRes.json();
    if (!tgInfo.ok || !tgInfo.result?.file_path) return res.status(502).json({ error: tgInfo.description || "getFile failed" });

    const fileRes = await fetch(`https://api.telegram.org/file/bot${TELEGRAM_BOT_TOKEN}/${tgInfo.result.file_path}`);
    if (!fileRes.ok) return res.status(502).json({ error: "Telegram download failed" });

    const buf = Buffer.from(await fileRes.arrayBuffer());
    res.setHeader("Content-Type", msg.mimeType || "application/octet-stream");
    res.setHeader("Cache-Control", "private, max-age=3600");
    return res.send(buf);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

apiRouter.post("/admin/block", requireFirebaseAuth, requireMainAdmin, async (req, res) => {
  try {
    const targetUid = String(req.body?.targetUid || "");
    const reason = String(req.body?.reason || "").trim();
    if (!targetUid || targetUid === MAIN_ADMIN_TELEGRAM_ID) return res.status(400).json({ error: "Invalid user ID" });

    const now = Date.now();
    const updates = {};
    updates[`supportChat/blockedUsers/${targetUid}`] = { blocked: true, reason, blockedBy: MAIN_ADMIN_TELEGRAM_ID, blockedAt: now };
    updates[`supportChat/users/${targetUid}/accountStatus`] = "blocked";
    const logRef = db.ref("supportChat/auditLogs").push();
    updates[`supportChat/auditLogs/${logRef.key}`] = { action: "block_user", actorId: MAIN_ADMIN_TELEGRAM_ID, targetUid, reason, createdAt: now };
    await db.ref().update(updates);
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

apiRouter.post("/admin/unblock", requireFirebaseAuth, requireMainAdmin, async (req, res) => {
  try {
    const targetUid = String(req.body?.targetUid || "");
    if (!targetUid) return res.status(400).json({ error: "Missing targetUid" });

    const now = Date.now();
    const updates = {};
    updates[`supportChat/blockedUsers/${targetUid}`] = { blocked: false, unblockedBy: MAIN_ADMIN_TELEGRAM_ID, unblockedAt: now };
    updates[`supportChat/users/${targetUid}/accountStatus`] = "active";
    const logRef = db.ref("supportChat/auditLogs").push();
    updates[`supportChat/auditLogs/${logRef.key}`] = { action: "unblock_user", actorId: MAIN_ADMIN_TELEGRAM_ID, targetUid, createdAt: now };
    await db.ref().update(updates);
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

apiRouter.post("/admin/settings", requireFirebaseAuth, requireMainAdmin, async (req, res) => {
  try {
    const allowed = ["supportName", "supportSubtitle", "supportLogo", "welcomeMessage", "welcomeEnabled", "contactAdminUrl", "defaultBlockedMessage"];
    const patch = {};
    for (const k of allowed) {
      if (req.body && k in req.body) patch[k] = req.body[k];
    }
    patch.updatedAt = Date.now();
    await db.ref("supportChat/settings").update(patch);
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

apiRouter.post("/admin/broadcast", requireFirebaseAuth, requireMainAdmin, async (req, res) => {
  try {
    const text = String(req.body?.text || "").trim();
    const file = req.body?.file || null;
    if (!text && !file) return res.status(400).json({ error: "Broadcast content required" });

    const [usersSnap, blockedSnap] = await Promise.all([db.ref("supportChat/users").get(), db.ref("supportChat/blockedUsers").get()]);
    const users = usersSnap.val() || {};
    const blocked = blockedSnap.val() || {};
    const eligibleIds = Object.keys(users).filter((uid) =>
      uid !== MAIN_ADMIN_TELEGRAM_ID && blocked[uid]?.blocked !== true && users[uid]?.accountStatus !== "blocked"
    );

    const bcRef = db.ref("supportChat/broadcasts").push();
    const broadcastId = bcRef.key;
    await bcRef.set({
      text, fileName: file?.fileName || null, total: eligibleIds.length,
      successCount: 0, failedCount: 0, status: eligibleIds.length ? "processing" : "completed",
      createdBy: MAIN_ADMIN_TELEGRAM_ID, createdAt: Date.now()
    });

    let successCount = 0;
    let failedCount = 0;
    for (const uid of eligibleIds) {
      try {
        const msgRef = db.ref(`supportChat/messages/${uid}`).push();
        const updates = {};
        updates[`supportChat/messages/${uid}/${msgRef.key}`] = {
          senderId: MAIN_ADMIN_TELEGRAM_ID, senderRole: "admin", type: file ? file.type : "text",
          text, fileId: file?.fileId || null, fileName: file?.fileName || null,
          mimeType: file?.mimeType || null, fileSize: file?.fileSize || null,
          isBroadcast: true, broadcastId, createdAt: admin.database.ServerValue.TIMESTAMP, deleted: false
        };
        updates[`supportChat/conversations/${uid}/lastMessageText`] = text || file?.fileName || "Broadcast";
        updates[`supportChat/conversations/${uid}/lastMessageAt`] = admin.database.ServerValue.TIMESTAMP;
        updates[`supportChat/conversations/${uid}/lastSenderRole`] = "admin";
        await db.ref().update(updates);
        await sendTelegramMessageToUser(uid, text, file).catch(() => {});
        successCount += 1;
      } catch (_) {
        failedCount += 1;
      }
      await bcRef.update({ successCount, failedCount });
    }
    await bcRef.update({ successCount, failedCount, status: "completed", completedAt: Date.now() });
    return res.json({ ok: true, broadcastId, total: eligibleIds.length, successCount, failedCount });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

apiRouter.use((req, res) => {
  res.status(404).json({ error: "API endpoint not found" });
});

app.use("/api", apiRouter);
app.use(express.static(path.join(__dirname, "..", "public")));
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "index.html"));
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Premium Support Chat Server listening on port ${PORT}`);
  });
}

module.exports = app;
