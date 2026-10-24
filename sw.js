// Carnet de Charge : fonctionnement hors ligne.
// La page est d'abord demandée au réseau (3 s max), pour qu'une nouvelle version
// arrive dès l'ouverture ; sans réseau, c'est la copie en cache qui s'affiche.
// Les autres fichiers sont servis depuis le cache puis mis à jour en arrière-plan.
// messages.json est toujours lu sur le réseau (jamais depuis le cache).
// Il affiche aussi les notifications envoyées par le serveur (push-server/).
// Les vidéos ne passent pas par le cache : Safari les lit par morceaux (requêtes Range).
const CACHE = "carnet-v5";
const SHELL = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/apple-touch-icon.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("push", (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; }
  catch (e) { data = { body: event.data ? event.data.text() : "" }; }
  event.waitUntil(self.registration.showNotification(data.title || "Carnet de Charge", {
    body: data.body || "",
    icon: "icons/icon-192.png",
    badge: "icons/icon-192.png",
    tag: data.tag || undefined,
    data: { url: data.url || "./" }
  }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const target = new URL((event.notification.data && event.notification.data.url) || "./", self.registration.scope).href;
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((wins) => {
      for (const w of wins) if (w.url.startsWith(self.registration.scope) && "focus" in w) return w.focus();
      return self.clients.openWindow(target);
    })
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.endsWith("/messages.json") || url.pathname.endsWith(".mp4")) return;

  if (req.mode === "navigate") {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE);
      try {
        const res = await Promise.race([
          fetch(req, { cache: "no-store" }),
          new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 3000))
        ]);
        if (res && res.ok) { cache.put("./index.html", res.clone()); return res; }
        throw new Error("bad status");
      } catch (e) {
        return (await cache.match("./index.html")) || (await cache.match(req, { ignoreSearch: true })) || fetch(req);
      }
    })());
    return;
  }

  event.respondWith(
    caches.open(CACHE).then(async (cache) => {
      const cached = await cache.match(req, { ignoreSearch: true });
      const network = fetch(req)
        .then((res) => {
          if (res && res.ok) cache.put(req, res.clone());
          return res;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});
