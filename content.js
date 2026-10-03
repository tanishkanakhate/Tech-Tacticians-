// 1) Scan the current page; 2) mark risky links on hover/click.
function banner(r) {
  const b = document.createElement("div");
  b.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:2147483647;padding:12px;color:#fff;font:600 15px system-ui;text-align:center;background:" + (r.verdict === "Phishing" ? "#d62839" : "#e08a00");
  b.textContent = `⚠️ PhishGuard: this page looks ${r.verdict.toUpperCase()} (score ${r.score}). ` + r.factors.map(f => f.name).join(", ");
  document.body.prepend(b);
}
chrome.runtime.sendMessage({type: "scan", url: location.href}, r => { if (r && r.verdict !== "Legitimate") banner(r); });

document.addEventListener("click", e => {
  const a = e.target.closest("a[href^='http']"); if (!a) return;
  if (a.dataset.pgOk) return;
  e.preventDefault();
  chrome.runtime.sendMessage({type: "scan", url: a.href}, r => {
    if (!r || r.verdict === "Legitimate" || confirm(`PhishGuard: ${r.verdict} (${r.score}/100)\n\n` + r.factors.map(f => "• " + f.detail).join("\n") + "\n\nOpen anyway?")) {
      a.dataset.pgOk = 1; a.click();
    }
  });
}, true);
