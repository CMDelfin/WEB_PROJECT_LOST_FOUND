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

document.addEventListener("DOMContentLoaded", () => {
  const registerForm = document.getElementById("registerForm");

  if (registerForm) {
    registerForm.addEventListener("submit", function (event) {
      event.preventDefault(); 

      const username = document.getElementById("username");
      const email = document.getElementById("email");
      const password = document.getElementById("password");

      let valid = true;

      if (username.value.trim().length < 3) {
        username.classList.add("is-invalid");
        valid = false;
      } else {
        username.classList.remove("is-invalid");
      }

      const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailPattern.test(email.value.trim())) {
        email.classList.add("is-invalid");
        valid = false;
      } else {
        email.classList.remove("is-invalid");
      }

      if (password.value.trim().length < 6) {
        password.classList.add("is-invalid");
        valid = false;
      } else {
        password.classList.remove("is-invalid");
      }

      if (valid) {
        registerForm.submit();
      }
    });
  }
});

document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("loginForm");

  if (loginForm) {
    loginForm.addEventListener("submit", function (event) {
      event.preventDefault();

      const email = document.getElementById("email");
      const password = document.getElementById("password");

      let valid = true;

      const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailPattern.test(email.value.trim())) {
        email.classList.add("is-invalid");
        valid = false;
      } else {
        email.classList.remove("is-invalid");
      }

      if (password.value.trim() === "") {
        password.classList.add("is-invalid");
        valid = false;
      } else {
        password.classList.remove("is-invalid");
      }

      if (valid) {
        loginForm.submit();
      }
    });
  }
});

window.addEventListener('scroll', revealElements);

function revealElements() {
  const reveals = document.querySelectorAll('.reveal');

  reveals.forEach(section => {
    const windowHeight = window.innerHeight;
    const revealTop = section.getBoundingClientRect().top;
    const revealPoint = 120;

    if (revealTop < windowHeight - revealPoint) {
      section.classList.add('active');
    } else {
      section.classList.remove('active');
    }
  });
}

document.addEventListener('DOMContentLoaded', revealElements);

const themeToggle = document.getElementById('theme-toggle');
if (themeToggle) {
  themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('dark-mode');
  });
}


