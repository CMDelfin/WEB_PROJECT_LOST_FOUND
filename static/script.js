document.addEventListener("DOMContentLoaded", () => {

  document.body.classList.add("fade-in");

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

  document.querySelectorAll(".alert").forEach(alert => {
    setTimeout(() => {
      alert.classList.remove("show");
      alert.classList.add("fade");
      setTimeout(() => alert.remove(), 1200);
    }, 3000);
  });

  const sidebar = document.getElementById("sidebar");
  const body = document.body;
  const sidebarToggle = document.getElementById("sidebarToggle");
  const closeSidebar = document.getElementById("closeSidebar");
  if (sidebarToggle) sidebarToggle.addEventListener("click", () => {
    sidebar.classList.add("active");
    body.classList.add("sidebar-open");
  });
  if (closeSidebar) closeSidebar.addEventListener("click", () => {
    sidebar.classList.remove("active");
    body.classList.remove("sidebar-open");
  });

  const darkToggle = document.getElementById("darkModeToggle");
  if (localStorage.getItem("theme") === "dark") {
    document.body.classList.add("dark-mode");
    if (darkToggle) darkToggle.textContent = "☀️ Light Mode";
  }
  if (darkToggle) darkToggle.addEventListener("click", () => {
    document.body.classList.toggle("dark-mode");
    const isDark = document.body.classList.contains("dark-mode");
    darkToggle.textContent = isDark ? "☀️ Light Mode" : "🌙 Dark Mode";
    localStorage.setItem("theme", isDark ? "dark" : "light");
  });

  const registerForm = document.getElementById("registerForm");
  if (registerForm) {
    registerForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      const username = document.getElementById("username");
      const email = document.getElementById("email");
      const password = document.getElementById("password");
      const phone = document.getElementById("phone");
      const registerBtn = document.getElementById("registerBtn");
      const btnText = document.getElementById("btnText");
      const btnSpinner = document.getElementById("btnSpinner");

      let valid = true;
      if (username.value.trim().length < 3) { username.classList.add("is-invalid"); valid = false; } else { username.classList.remove("is-invalid"); }
      const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailPattern.test(email.value.trim())) { email.classList.add("is-invalid"); valid = false; } else { email.classList.remove("is-invalid"); }
      if (password.value.trim().length < 6) { password.classList.add("is-invalid"); valid = false; } else { password.classList.remove("is-invalid"); }
      if (!valid) return;

      btnText.style.display = "none";
      btnSpinner.style.display = "inline-block";
      registerBtn.disabled = true;

      const payload = {
        username: username.value.trim(),
        email: email.value.trim(),
        password: password.value.trim(),
        phone: phone ? phone.value.trim() : ''
      };

      try {
        const response = await fetch("/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (data.status === "otp_sent") {
          const otpModal = new bootstrap.Modal(document.getElementById("otpModal"));
          otpModal.show();

          const verifyBtn = document.getElementById("verifyOtpBtn");
          const otpInput = document.getElementById("otpInput");
          const otpError = document.getElementById("otpError");
          const otpBtnText = document.getElementById("otpBtnText");
          const otpSpinner = document.getElementById("otpSpinner");

          verifyBtn.onclick = async () => {
            const otp = otpInput.value.trim();
            if (otp.length !== 6) { otpError.textContent = "Enter a 6-digit OTP"; otpError.style.display = "block"; return; }

            otpBtnText.style.display = "none";
            otpSpinner.style.display = "inline-block";
            verifyBtn.disabled = true;

            try {
              const otpResp = await fetch("/verify_otp", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ otp })
              });

              const otpData = await otpResp.json();
              if (otpData.status === "success") {
                otpError.style.display = "none";
                otpModal.hide();
                window.location.href = "/login";
              } else {
                otpError.textContent = otpData.message || "Invalid OTP";
                otpError.style.display = "block";
              }
            } catch {
              otpError.textContent = "Error connecting to server.";
              otpError.style.display = "block";
            } finally {
              otpBtnText.style.display = "inline";
              otpSpinner.style.display = "none";
              verifyBtn.disabled = false;
            }
          };

        } else {
          alert(data.message || "Registration failed");
          btnText.style.display = "inline";
          btnSpinner.style.display = "none";
          registerBtn.disabled = false;
        }

      } catch (err) {
        alert("Error connecting to server.");
        btnText.style.display = "inline";
        btnSpinner.style.display = "none";
        registerBtn.disabled = false;
        console.error(err);
      }
    });
  }

  const loginForm = document.getElementById("loginForm");
  if (loginForm) {
    loginForm.addEventListener("submit", function (event) {
      event.preventDefault();
      const email = document.getElementById("email");
      const password = document.getElementById("password");

      let valid = true;
      const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailPattern.test(email.value.trim())) { email.classList.add("is-invalid"); valid = false; } else { email.classList.remove("is-invalid"); }
      if (password.value.trim() === "") { password.classList.add("is-invalid"); valid = false; } else { password.classList.remove("is-invalid"); }
      if (valid) loginForm.submit();
    });
  }

  function revealElements() {
    const reveals = document.querySelectorAll('.reveal');
    reveals.forEach(section => {
      const windowHeight = window.innerHeight;
      const revealTop = section.getBoundingClientRect().top;
      const revealPoint = 120;
      if (revealTop < windowHeight - revealPoint) section.classList.add('active');
      else section.classList.remove('active');
    });
  }
  window.addEventListener('scroll', revealElements);
  revealElements();
});
