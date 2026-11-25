import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

// Prevent trackpad pinch-to-zoom, hotkey zoom, middle-click autoscroll, and
// accidental root viewport panning inside the desktop WebView.
window.addEventListener(
  "wheel",
  (e) => {
    if (e.ctrlKey) {
      e.preventDefault();
    }
  },
  { passive: false }
);

window.addEventListener("keydown", (e) => {
  if (
    (e.ctrlKey || e.metaKey) &&
    (e.key === "+" || e.key === "=" || e.key === "-" || e.key === "_" || e.key === "0")
  ) {
    e.preventDefault();
  }
});

window.addEventListener("mousedown", (e) => {
  if (e.button === 1) {
    e.preventDefault();
  }
});

window.addEventListener("scroll", () => {
  if (window.scrollX !== 0 || window.scrollY !== 0) {
    window.scrollTo(0, 0);
  }
  if (document.documentElement.scrollLeft !== 0 || document.documentElement.scrollTop !== 0) {
    document.documentElement.scrollLeft = 0;
    document.documentElement.scrollTop = 0;
  }
});

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
