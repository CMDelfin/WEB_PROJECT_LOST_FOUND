document.addEventListener("DOMContentLoaded", () => {

  document.body.classList.add("fade-in");

  // Page navigation transitions
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

  // Auto-hide alerts
  document.querySelectorAll(".alert").forEach(alert => {
    setTimeout(() => {
      alert.classList.remove("show");
      alert.classList.add("fade");
      setTimeout(() => alert.remove(), 1200);
    }, 3000);
  });

  // Sidebar toggle
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

  // Dark mode toggle
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

  // Register form
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

  // Reveal elements on scroll
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

  // --- Forgot Password Modal ---
  const forgotLink = document.getElementById('forgotPasswordLink');
  const forgotModalEl = document.getElementById('forgotModal');
  let forgotModal;
  if (forgotModalEl) forgotModal = new bootstrap.Modal(forgotModalEl);

  const fpStepEmail = document.getElementById('fp-step-email');
  const fpStepOtp = document.getElementById('fp-step-otp');
  const fpStepNewPass = document.getElementById('fp-step-newpass');

  const fpEmailInput = document.getElementById('fp-email');
  const fpEmailError = document.getElementById('fp-email-error');
  const fpSentEmailSpan = document.getElementById('fp-sent-email');
  const fpOtpInput = document.getElementById('fp-otp');
  const fpOtpError = document.getElementById('fp-otp-error');
  const fpNewPassInput = document.getElementById('fp-new-password');
  const fpNewPassError = document.getElementById('fp-newpass-error');

  const fpSendOtpBtn = document.getElementById('fp-send-otp-btn');
  const fpVerifyOtpBtn = document.getElementById('fp-verify-otp-btn');
  const fpResetPassBtn = document.getElementById('fp-reset-pass-btn');
  const fpVerifySpinner = document.getElementById('fp-verify-spinner');
  const fpResetSpinner = document.getElementById('fp-reset-spinner');

  function resetForgotModalUI() {
    fpStepEmail.style.display = '';
    fpStepOtp.style.display = 'none';
    fpStepNewPass.style.display = 'none';
    fpSendOtpBtn.style.display = '';
    fpVerifyOtpBtn.style.display = 'none';
    fpResetPassBtn.style.display = 'none';
    fpEmailInput.value = '';
    fpOtpInput.value = '';
    fpNewPassInput.value = '';
    fpEmailError.style.display = 'none';
    fpOtpError.style.display = 'none';
    fpNewPassError.style.display = 'none';

    // Apply dark mode to modal dynamically
    const modalContent = forgotModalEl.querySelector('.modal-content');
    if (document.body.classList.contains('dark-mode')) {
        modalContent.classList.add('dark-mode-modal');
    } else {
        modalContent.classList.remove('dark-mode-modal');
    }
}


  if (forgotLink) {
    forgotLink.addEventListener('click', (e) => {
      e.preventDefault();
      resetForgotModalUI();
      if (forgotModal) forgotModal.show();
    });
  }

  // Send OTP
  if (fpSendOtpBtn) {
    fpSendOtpBtn.addEventListener('click', async () => {
      fpEmailError.style.display = 'none';
      const email = fpEmailInput.value.trim();
      const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailPattern.test(email)) {
        fpEmailError.textContent = 'Please enter a valid email.';
        fpEmailError.style.display = 'block';
        return;
      }

      fpSendOtpBtn.disabled = true;
      fpSendOtpBtn.textContent = 'Sending...';

      try {
        const res = await fetch('/forgot_password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email })
        });
        const data = await res.json();
        if (data.status === 'otp_sent') {
          fpStepEmail.style.display = 'none';
          fpStepOtp.style.display = '';
          fpStepNewPass.style.display = 'none';
          fpSendOtpBtn.style.display = 'none';
          fpVerifyOtpBtn.style.display = '';
          fpResetPassBtn.style.display = 'none';
          fpSentEmailSpan.textContent = email;
        } else {
          fpEmailError.textContent = data.message || 'Failed to send OTP.';
          fpEmailError.style.display = 'block';
        }
      } catch (err) {
        fpEmailError.textContent = 'Error connecting to server.';
        fpEmailError.style.display = 'block';
        console.error(err);
      } finally {
        fpSendOtpBtn.disabled = false;
        fpSendOtpBtn.textContent = 'Send OTP';
      }
    });
  }

  // Verify OTP
  if (fpVerifyOtpBtn) {
    fpVerifyOtpBtn.addEventListener('click', async () => {
      fpOtpError.style.display = 'none';
      const otp = fpOtpInput.value.trim();
      if (otp.length !== 6) {
        fpOtpError.textContent = 'Enter a 6-digit OTP.';
        fpOtpError.style.display = 'block';
        return;
      }

      fpVerifyOtpBtn.disabled = true;
      fpVerifySpinner.style.display = 'inline-block';

      try {
        const res = await fetch('/verify_reset_otp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ otp })
        });
        const data = await res.json();
        if (data.status === 'verified') {
          fpStepEmail.style.display = 'none';
          fpStepOtp.style.display = 'none';
          fpStepNewPass.style.display = '';
          fpSendOtpBtn.style.display = 'none';
          fpVerifyOtpBtn.style.display = 'none';
          fpResetPassBtn.style.display = '';
        } else {
          fpOtpError.textContent = data.message || 'Invalid OTP.';
          fpOtpError.style.display = 'block';
        }
      } catch (err) {
        fpOtpError.textContent = 'Error connecting to server.';
        fpOtpError.style.display = 'block';
        console.error(err);
      } finally {
        fpVerifyOtpBtn.disabled = false;
        fpVerifySpinner.style.display = 'none';
      }
    });
  }

  // Reset Password
  if (fpResetPassBtn) {
    fpResetPassBtn.addEventListener('click', async () => {
      fpNewPassError.style.display = 'none';
      const newPass = fpNewPassInput.value.trim();
      if (newPass.length < 6) {
        fpNewPassError.textContent = 'Password must be at least 6 characters.';
        fpNewPassError.style.display = 'block';
        return;
      }

      fpResetPassBtn.disabled = true;
      fpResetSpinner.style.display = 'inline-block';

      try {
        const res = await fetch('/reset_password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ new_password: newPass })
        });
        const data = await res.json();
        if (data.status === 'success') {
          if (forgotModal) forgotModal.hide();
          const a = document.createElement('div');
          a.className = 'alert alert-success';
          a.textContent = 'Password reset successful. You can now log in.';
          document.body.appendChild(a);
          setTimeout(() => { a.classList.add('fade'); setTimeout(()=>a.remove(), 1200); }, 2500);
        } else {
          fpNewPassError.textContent = data.message || 'Failed to reset password.';
          fpNewPassError.style.display = 'block';
        }
      } catch (err) {
        fpNewPassError.textContent = 'Error connecting to server.';
        fpNewPassError.style.display = 'block';
        console.error(err);
      } finally {
        fpResetPassBtn.disabled = false;
        fpResetSpinner.style.display = 'none';
      }
    });
  }

  // Reset modal UI on close
  if (forgotModalEl) {
    forgotModalEl.addEventListener('hidden.bs.modal', () => {
      resetForgotModalUI();
    });
  }

});