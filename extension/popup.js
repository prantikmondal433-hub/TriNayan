// TrustLens Extension - Toolbar Popup Logic
document.addEventListener("DOMContentLoaded", () => {
  const urlEl = document.getElementById("url");
  const scoreEl = document.getElementById("score");
  const badgeEl = document.getElementById("badge");
  const reasonsEl = document.getElementById("reasons");
  const detailsLink = document.getElementById("details-link");
  const reportLink = document.getElementById("report-link");

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || tabs.length === 0) return;
    const currentUrl = tabs[0].url;

    if (!currentUrl || currentUrl.startsWith("chrome://")) {
      urlEl.innerText = "System / Internal page";
      scoreEl.innerText = "0";
      badgeEl.innerText = "N/A";
      reasonsEl.innerText = "Internal browser pages are not scanned.";
      return;
    }

    urlEl.innerText = currentUrl;
    detailsLink.href = `http://localhost:3000/result?url=${encodeURIComponent(currentUrl)}`;
    reportLink.href = `http://localhost:3000/report?url=${encodeURIComponent(currentUrl)}`;

    chrome.runtime.sendMessage(
      { action: "CHECK_URL", url: currentUrl },
      (response) => {
        if (!response || !response.result) {
          scoreEl.innerText = "??";
          badgeEl.innerText = "Error";
          return;
        }

        const { risk, verdict, reasons } = response.result;
        scoreEl.innerText = risk;
        scoreEl.style.color =
          risk >= 70 ? "#ef4444" : risk >= 35 ? "#f59e0b" : "#10b981";

        badgeEl.innerText = verdict;
        badgeEl.className = `badge badge-${verdict.toLowerCase()}`;

        if (reasons && reasons.length > 0) {
          const list = reasons
            .slice(0, 3)
            .map((r) => `• ${typeof r === "string" ? r : r.title}`)
            .join("<br/>");
          reasonsEl.innerHTML = list;
        } else {
          reasonsEl.innerText = "No critical risk triggers detected.";
        }
      }
    );
  });
});
