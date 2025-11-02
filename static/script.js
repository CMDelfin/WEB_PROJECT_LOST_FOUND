document.addEventListener("DOMContentLoaded", () => {
  document.body.classList.add("fade-in");
});

document.querySelectorAll("a").forEach(link => {
  const href = link.getAttribute("href");
  if (href && !href.startsWith("#") && !href.startsWith("http")) {
    link.addEventListener("click", e => {
      e.preventDefault();
      document.body.classList.add("fade-out");
      setTimeout(() => window.location.href = href, 300);
    });
  }
});

const alerts = document.querySelectorAll(".alert");
alerts.forEach(alert => {
  setTimeout(() => {
    alert.classList.remove("show");
    alert.classList.add("fade");
    setTimeout(() => alert.remove(), 1200);
  }, 3000);
});

const sidebar = document.getElementById("sidebar");
const body = document.body;

document.getElementById("sidebarToggle").addEventListener("click", () => {
  sidebar.classList.add("active");
  body.classList.add("sidebar-open");
});

document.getElementById("closeSidebar").addEventListener("click", () => {
  sidebar.classList.remove("active");
  body.classList.remove("sidebar-open");
});

const toggle = document.getElementById("darkModeToggle");
if (localStorage.getItem("theme") === "dark") {
  document.body.classList.add("dark-mode");
  toggle.textContent = "☀️ Light Mode";
}

toggle.addEventListener("click", () => {
  document.body.classList.toggle("dark-mode");
  const isDark = document.body.classList.contains("dark-mode");
  toggle.textContent = isDark ? "☀️ Light Mode" : "🌙 Dark Mode";
  localStorage.setItem("theme", isDark ? "dark" : "light");
});

