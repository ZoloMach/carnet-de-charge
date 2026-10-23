// Serveur de notifications de Carnet de Charge (Cloudflare Worker).
//
//   POST /subscribe    enregistre ou met à jour l'abonnement d'un téléphone
//   POST /unsubscribe  retire un abonnement
//   POST /test         envoie une notification de test à un abonnement
//   cron (15 min)      envoie les rappels d'entraînement et les nouveaux messages de messages.json
//
// Stocké par téléphone (KV « SUBS ») : l'adresse de notification, le pseudo facultatif,
// les réglages de rappel, le fuseau horaire et le nom de la prochaine séance. Jamais les séances.
// Chiffrement Web Push (RFC 8291, aes128gcm) et signature VAPID (RFC 8292) en WebCrypto.

const enc = new TextEncoder();

function b64uToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64u(buf) {
  const a = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
function normalize(s) {
  return String(s || "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").trim();
}

async function hkdf(salt, ikm, info, length) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, length * 8));
}

async function vapidHeader(endpoint, env) {
  const pub = b64uToBytes(env.VAPID_PUBLIC_KEY);
  const jwk = {
    kty: "EC", crv: "P-256", ext: true,
    x: bytesToB64u(pub.slice(1, 33)), y: bytesToB64u(pub.slice(33, 65)), d: env.VAPID_PRIVATE_KEY
  };
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const header = bytesToB64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = bytesToB64u(enc.encode(JSON.stringify({
    aud: new URL(endpoint).origin,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: env.VAPID_SUBJECT
  })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(header + "." + claims));
  return `vapid t=${header}.${claims}.${bytesToB64u(sig)}, k=${env.VAPID_PUBLIC_KEY}`;
}

async function encryptPayload(sub, text) {
  const uaPublic = b64uToBytes(sub.keys.p256dh);
  const authSecret = b64uToBytes(sub.keys.auth);
  const local = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", local.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, local.privateKey, 256));

  const ikm = await hkdf(authSecret, shared, concat(enc.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);

  const aesKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const plain = concat(enc.encode(text), new Uint8Array([2]));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, plain));

  const head = new Uint8Array(21 + asPublic.length);
  head.set(salt, 0);
  new DataView(head.buffer).setUint32(16, 4096);
  head[20] = asPublic.length;
  head.set(asPublic, 21);
  return concat(head, cipher);
}

// Renvoie le code HTTP du service de notification (201 = envoyé, 404/410 = abonnement expiré).
async function sendPush(env, sub, data) {
  const res = await fetch(sub.endpoint, {
    method: "POST",
    headers: {
      Authorization: await vapidHeader(sub.endpoint, env),
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      TTL: "86400",
      Urgency: "normal"
    },
    body: await encryptPayload(sub, JSON.stringify(data))
  });
  return res.status;
}

async function subKey(endpoint) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(endpoint)));
  return "sub:" + [...h].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 40);
}

function corsHeaders(req, env) {
  const allowed = String(env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
  const origin = req.headers.get("Origin");
  return {
    "Access-Control-Allow-Origin": allowed.includes(origin) ? origin : allowed[0] || "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin"
  };
}
function json(req, env, status, obj) {
  return new Response(JSON.stringify(obj), { status, headers: { ...corsHeaders(req, env), "Content-Type": "application/json" } });
}

function validSubscription(s) {
  return s && typeof s.endpoint === "string" && s.endpoint.startsWith("https://") && s.endpoint.length < 2000
    && s.keys && typeof s.keys.p256dh === "string" && typeof s.keys.auth === "string";
}
function validTimeZone(tz) {
  try { new Intl.DateTimeFormat("en-GB", { timeZone: tz }); return true; } catch (e) { return false; }
}
function cleanReminder(r) {
  const days = Array.isArray(r && r.days) ? [...new Set(r.days.map(Number).filter((d) => d >= 0 && d <= 6))] : [];
  const time = r && /^([01]\d|2[0-3]):[0-5]\d$/.test(r.time) ? r.time : "18:00";
  return { on: !!(r && r.on), days, time };
}

async function handleSubscribe(req, env, ctx) {
  const body = await req.json().catch(() => null);
  if (!body || !validSubscription(body.subscription)) return json(req, env, 400, { error: "abonnement invalide" });
  const sub = { endpoint: body.subscription.endpoint, keys: { p256dh: body.subscription.keys.p256dh, auth: body.subscription.keys.auth } };
  const key = await subKey(sub.endpoint);
  const prev = await env.SUBS.get(key, "json");
  const rec = {
    sub,
    name: String(body.name || "").slice(0, 40),
    reminder: cleanReminder(body.reminder),
    tz: validTimeZone(body.tz) ? body.tz : "Europe/Paris",
    next: String(body.next || "").slice(0, 40),
    lastReminder: prev ? prev.lastReminder || null : null,
    created: prev ? prev.created : Date.now(),
    updated: Date.now()
  };
  await env.SUBS.put(key, JSON.stringify(rec));
  if (!prev && body.welcome !== false) {
    ctx.waitUntil(sendPush(env, sub, {
      title: "Notifications activées",
      body: "Tu recevras ici tes rappels d'entraînement et les messages de l'appli.",
      tag: "bienvenue"
    }).catch(() => {}));
  }
  return json(req, env, 200, { ok: true });
}

async function handleUnsubscribe(req, env) {
  const body = await req.json().catch(() => null);
  if (!body || typeof body.endpoint !== "string") return json(req, env, 400, { error: "adresse manquante" });
  await env.SUBS.delete(await subKey(body.endpoint));
  return json(req, env, 200, { ok: true });
}

async function handleTest(req, env) {
  const body = await req.json().catch(() => null);
  if (!body || typeof body.endpoint !== "string") return json(req, env, 400, { error: "adresse manquante" });
  const key = await subKey(body.endpoint);
  const rec = await env.SUBS.get(key, "json");
  if (!rec) return json(req, env, 404, { error: "abonnement inconnu" });
  const status = await sendPush(env, rec.sub, {
    title: "Test réussi",
    body: rec.next ? `Les notifications marchent. Prochaine séance : ${rec.next}.` : "Les notifications marchent.",
    tag: "test"
  });
  if (status === 404 || status === 410) await env.SUBS.delete(key);
  return json(req, env, 200, { ok: status >= 200 && status < 300, status });
}

// ---------- tâche planifiée ----------
async function allSubs(env) {
  const out = [];
  let cursor;
  do {
    const page = await env.SUBS.list({ prefix: "sub:", cursor });
    for (const k of page.keys) {
      const rec = await env.SUBS.get(k.name, "json");
      if (rec) out.push({ key: k.name, rec });
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  return out;
}

function localNow(tz) {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", weekday: "short", hourCycle: "h23"
  }).formatToParts(new Date());
  const p = Object.fromEntries(parts.map((x) => [x.type, x.value]));
  return {
    date: `${p.year}-${p.month}-${p.day}`,
    minutes: Number(p.hour) * 60 + Number(p.minute),
    weekday: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(p.weekday)
  };
}

async function deliver(env, item, data) {
  try {
    const status = await sendPush(env, item.rec.sub, data);
    if (status === 404 || status === 410) { await env.SUBS.delete(item.key); return false; }
    return status >= 200 && status < 300;
  } catch (e) {
    return false;
  }
}

async function sendReminders(env, subs) {
  for (const item of subs) {
    const r = item.rec.reminder;
    if (!r || !r.on || !r.days.length) continue;
    const now = localNow(item.rec.tz || "Europe/Paris");
    if (!r.days.includes(now.weekday) || item.rec.lastReminder === now.date) continue;
    const [h, m] = r.time.split(":").map(Number);
    const target = h * 60 + m;
    if (now.minutes < target || now.minutes >= target + 30) continue;
    await deliver(env, item, {
      title: item.rec.next ? `Au programme : ${item.rec.next}` : "C'est l'heure de ta séance",
      body: "Ouvre ton carnet pour voir tes charges du jour.",
      tag: "rappel"
    });
    item.rec.lastReminder = now.date;
    await env.SUBS.put(item.key, JSON.stringify(item.rec));
  }
}

async function sendMessages(env, subs) {
  let list;
  try {
    const res = await fetch(env.MESSAGES_URL + "?t=" + Date.now(), { cf: { cacheTtl: 0 } });
    if (!res.ok) return;
    const j = await res.json();
    list = Array.isArray(j) ? j : (Array.isArray(j.messages) ? j.messages : []);
  } catch (e) {
    return;
  }
  const today = new Date().toISOString().slice(0, 10);
  for (const m of list) {
    if (!m || !m.id || !m.text || m.push === false) continue;
    if (m.until && m.until < today) continue;
    const flag = "pushed:" + m.id;
    if (await env.SUBS.get(flag)) continue;
    const to = (Array.isArray(m.to) ? m.to : [m.to || "*"]).map(String);
    const not = Array.isArray(m.not) ? m.not.map(normalize) : [];
    for (const item of subs) {
      const me = normalize(item.rec.name);
      if (me && not.includes(me)) continue;
      if (!to.some((x) => x === "*" || (me && normalize(x) === me))) continue;
      await deliver(env, item, { title: m.title || "Carnet de Charge", body: m.text, tag: "msg-" + m.id });
    }
    await env.SUBS.put(flag, "1", { expirationTtl: 60 * 60 * 24 * 120 });
  }
}

// Exposées uniquement pour les tests de chiffrement et de signature.
export { encryptPayload as _encryptPayload, vapidHeader as _vapidHeader };

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(req, env) });
    if (req.method === "GET" && url.pathname === "/") return json(req, env, 200, { ok: true, service: "carnet-de-charge-push" });
    if (req.method === "POST" && url.pathname === "/subscribe") return handleSubscribe(req, env, ctx);
    if (req.method === "POST" && url.pathname === "/unsubscribe") return handleUnsubscribe(req, env);
    if (req.method === "POST" && url.pathname === "/test") return handleTest(req, env);
    return json(req, env, 404, { error: "introuvable" });
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      const subs = await allSubs(env);
      if (!subs.length) return;
      await sendReminders(env, subs);
      await sendMessages(env, subs);
    })());
  }
};
