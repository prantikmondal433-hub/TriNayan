// TrustLens Content Script - Passive in-page safety banner
(function () {
  const currentUrl = window.location.href;

  // Don't inject on internal trustlens pages or chrome extensions
  if (
    currentUrl.startsWith("http://localhost:3000") ||
    currentUrl.startsWith("chrome://") ||
    currentUrl.startsWith("chrome-extension://")
  ) {
    return;
  }

  chrome.runtime.sendMessage(
    { action: "CHECK_URL", url: currentUrl },
    (response) => {
      if (!response || !response.result) return;
      const { verdict, risk, reasons } = response.result;

      if (verdict === "Dangerous" || verdict === "Suspicious") {
        injectWarningBanner(verdict, risk, reasons);
      }
    }
  );

  function injectWarningBanner(verdict, risk, reasons) {
    if (document.getElementById("trustlens-warning-banner")) return;

    const banner = document.createElement("div");
    banner.id = "trustlens-warning-banner";
    const isDangerous = verdict === "Dangerous";
    const bg = isDangerous ? "#dc2626" : "#d97706";
    const firstReason = reasons && reasons.length > 0
      ? (typeof reasons[0] === "string" ? reasons[0] : reasons[0].title)
      : "Potential security or impersonation risk detected";

    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 2147483647;
      background: ${bg};
      color: #ffffff;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      padding: 10px 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 4px 14px rgba(0,0,0,0.4);
      font-size: 13px;
      line-height: 1.4;
    `;

    const explanationUrl = `http://localhost:3000/result?url=${encodeURIComponent(currentUrl)}`;

    banner.innerHTML = `
      <div style="display: flex; items: center; gap: 8px;">
        <span style="font-size: 16px;">${isDangerous ? "🚨" : "⚠️"}</span>
        <span>
          <strong>TrustLens Alert:</strong> This site is flagged as <strong>${verdict}</strong> (Risk: ${risk}/100).
          <span style="opacity: 0.9; margin-left: 6px;">${firstReason}</span>
        </span>
      </div>
      <div style="display: flex; align-items: center; gap: 10px;">
        <a href="${explanationUrl}" target="_blank" style="
          background: rgba(255,255,255,0.25);
          color: white;
          text-decoration: none;
          padding: 4px 10px;
          border-radius: 4px;
          font-weight: 600;
          font-size: 12px;
        ">Why is this unsafe? →</a>
        <button id="trustlens-dismiss-btn" style="
          background: transparent;
          border: none;
          color: white;
          cursor: pointer;
          font-size: 16px;
          padding: 2px 6px;
        ">✕</button>
      </div>
    `;

    document.body.prepend(banner);

    document.getElementById("trustlens-dismiss-btn")?.addEventListener("click", () => {
      banner.remove();
    });
  }
})();
