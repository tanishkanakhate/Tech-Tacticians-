// Content scripts can't call localhost directly on https pages, so the service worker relays.
const cache = {};
chrome.runtime.onMessage.addListener((msg, _s, send) => {
  if (msg.type !== "scan") return;
  if (cache[msg.url]) { send(cache[msg.url]); return; }
  fetch("http://localhost:5000/api/analyze", {
    method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({url: msg.url})
  }).then(r => r.json()).then(d => { cache[msg.url] = d; send(d); }).catch(() => send(null));
  return true; // async response
});
