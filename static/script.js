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
const phone = document.getElementById("phone");

if (phone) {
  phone.addEventListener("input", () => {
    phone.value = phone.value.replace(/\D/g, "");
    if (phone.value.length > 11) {
      phone.value = phone.value.slice(0, 11);
    }
  });
}

if (registerForm) {
  registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = document.getElementById("username");
    const email = document.getElementById("email");
    const password = document.getElementById("password");
    const registerBtn = document.getElementById("registerBtn");
    const btnText = document.getElementById("btnText");
    const btnSpinner = document.getElementById("btnSpinner");

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

    if (phone.value && phone.value.length !== 11) {
      phone.classList.add("is-invalid");
      valid = false;
    } else {
      phone.classList.remove("is-invalid");
    }

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
  const loginOtpModalEl = document.getElementById("loginOtpModal");
  let loginOtpModal = null;
  if (loginOtpModalEl) loginOtpModal = new bootstrap.Modal(loginOtpModalEl);

  const loginOtpInput = document.getElementById("loginOtpInput");
  const loginOtpError = document.getElementById("loginOtpError");
  const loginVerifyOtpBtn = document.getElementById("loginVerifyOtpBtn");
  const loginOtpBtnText = document.getElementById("loginOtpBtnText");
  const loginOtpSpinner = document.getElementById("loginOtpSpinner");

  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const loginBtn = document.getElementById("loginBtn");
      const btnText = document.getElementById("btnText");
      const btnSpinner = document.getElementById("btnSpinner");
      btnText.style.display = "none";
      btnSpinner.style.display = "inline-block";
      loginBtn.disabled = true;
      loginOtpError.style.display = "none";

      const email = document.getElementById("email").value.trim();
      const password = document.getElementById("password").value.trim();

      try {
        const res = await fetch("/login_request_otp", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password })
        });
        const data = await res.json();

        if (data.status === "error") {
          alert(data.message || "Login failed.");
          return;
        }

        if (data.status === "success" && data.redirect) {
          window.location.href = data.redirect;
          return;
        }

        if (data.status === "otp_sent") {
          loginOtpInput.value = "";
          loginOtpError.style.display = "none";
          if (loginOtpModal) loginOtpModal.show();
          return;
        }

        alert("Unexpected response from server.");
      } catch (err) {
        console.error(err);
        alert("Error connecting to server.");
      } finally {

        btnText.style.display = "inline";
        btnSpinner.style.display = "none";
        loginBtn.disabled = false;
      }
    });
  }

  if (loginVerifyOtpBtn) {
    loginVerifyOtpBtn.addEventListener("click", async () => {
      loginOtpError.style.display = "none";
      const otp = loginOtpInput.value.trim();

      if (!/^\d{6}$/.test(otp)) {
        loginOtpError.textContent = "Enter a valid 6-digit OTP.";
        loginOtpError.style.display = "block";
        return;
      }

      loginOtpBtnText.style.display = "none";
      loginOtpSpinner.style.display = "inline-block";
      loginVerifyOtpBtn.disabled = true;

      try {
        const res = await fetch("/login_verify_otp", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ otp })
        });
        const data = await res.json();

        if (data.status === "error") {
          loginOtpError.textContent = data.message || "Invalid OTP.";
          loginOtpError.style.display = "block";
          return;
        }

        if (data.status === "success") {

          if (loginOtpModal) loginOtpModal.hide();
          window.location.href = data.redirect || "/dashboard";
          return;
        }

        loginOtpError.textContent = "Unexpected response from server.";
        loginOtpError.style.display = "block";

      } catch (err) {
        console.error(err);
        loginOtpError.textContent = "Error connecting to server.";
        loginOtpError.style.display = "block";
      } finally {
        loginOtpBtnText.style.display = "inline";
        loginOtpSpinner.style.display = "none";
        loginVerifyOtpBtn.disabled = false;
      }
    });
  }

  function revealElements() {
    document.querySelectorAll('.reveal').forEach(section => {
      const windowHeight = window.innerHeight;
      const revealTop = section.getBoundingClientRect().top;
      const revealPoint = 120;
      if (revealTop < windowHeight - revealPoint) section.classList.add('active');
      else section.classList.remove('active');
    });
  }
  window.addEventListener('scroll', revealElements);
  revealElements();

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

    const modalContent = forgotModalEl.querySelector('.modal-content');
    if (document.body.classList.contains('dark-mode')) modalContent.classList.add('dark-mode-modal');
    else modalContent.classList.remove('dark-mode-modal');
  }

  if (forgotLink) {
    forgotLink.addEventListener('click', e => {
      e.preventDefault();
      resetForgotModalUI();
      if (forgotModal) forgotModal.show();
    });
  }

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

  if (forgotModalEl) {
    forgotModalEl.addEventListener('hidden.bs.modal', () => {
      resetForgotModalUI();
    });
  }

});

document.querySelectorAll(".save-user-btn").forEach(button => {
    button.addEventListener("click", async () => {
      const row = button.closest("tr");
      const userId = row.dataset.userId;
      const username = row.querySelector("[data-field='username']").textContent.trim();
      const email = row.querySelector("[data-field='email']").textContent.trim();
      const phone = row.querySelector("[data-field='phone']").textContent.trim();

      button.disabled = true;
      const originalText = button.textContent;
      button.textContent = 'Saving...';

      try {
        const res = await fetch("/admin_edit_user", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: userId, username, email, phone })
        });
        const data = await res.json();
        if (data.status === "success") {
          button.textContent = "Saved!";
          setTimeout(() => { button.textContent = originalText; button.disabled = false; }, 1000);
        } else {
          alert(data.message || "Failed to update user.");
          button.textContent = originalText;
          button.disabled = false;
        }
      } catch (err) {
        alert("Error connecting to server.");
        button.textContent = originalText;
        button.disabled = false;
        console.error(err);
      }
    });
  });

  document.querySelectorAll(".delete-user-btn").forEach(button => {
    button.addEventListener("click", async () => {
      const row = button.closest("tr");
      const userId = row.dataset.userId;

      if (!confirm("Are you sure you want to delete this user?")) return;

      button.disabled = true;
      const originalText = button.textContent;
      button.textContent = "Deleting...";

      try {
        const res = await fetch("/admin_delete_user", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: userId })
        });
        const data = await res.json();
        if (data.status === "success") {
          row.remove();
        } else {
          alert(data.message || "Failed to delete user.");
          button.textContent = originalText;
          button.disabled = false;
        }
      } catch (err) {
        alert("Error connecting to server.");
        button.textContent = originalText;
        button.disabled = false;
        console.error(err);
      }
    });
  });

document.addEventListener("DOMContentLoaded", () => {

  const editUserModalEl = document.getElementById('editUserModal');
  const editUserForm = document.getElementById('editUserForm');
  const editUserId = document.getElementById('editUserId');
  const editUsername = document.getElementById('editUsername');
  const editEmail = document.getElementById('editEmail');
  const editPhone = document.getElementById('editPhone');
  const editUserError = document.getElementById('editUserError');

  if (editUserModalEl) {
    editUserModalEl.addEventListener('show.bs.modal', (event) => {
      const button = event.relatedTarget;
      editUserId.value = button.getAttribute('data-user-id');
      editUsername.value = button.getAttribute('data-username');
      editEmail.value = button.getAttribute('data-email');
      editPhone.value = button.getAttribute('data-phone') || '';
      editUserError.style.display = 'none';
    });
  }

  if (editUserForm) {
    editUserForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      editUserError.style.display = 'none';

      const payload = {
        id: editUserId.value,
        username: editUsername.value.trim(),
        email: editEmail.value.trim(),
        phone: editPhone.value.trim()
      };

      const submitBtn = editUserForm.querySelector("button[type='submit']");
      const originalText = submitBtn.textContent;
      submitBtn.disabled = true;
      submitBtn.textContent = "Saving...";

      try {
        const res = await fetch('/admin_edit_user', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.status === 'success') {
          location.reload();
        } else {
          editUserError.textContent = data.message || 'Failed to update user.';
          editUserError.style.display = 'block';
        }
      } catch (err) {
        editUserError.textContent = 'Error connecting to server.';
        editUserError.style.display = 'block';
        console.error(err);
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
      }
    });
  }


  document.querySelectorAll(".delete-user-btn").forEach(button => {
    button.addEventListener("click", async () => {
      const row = button.closest("tr");
      const userId = row.dataset.userId;

      if (!confirm("Are you sure you want to delete this user?")) return;

      button.disabled = true;
      const originalText = button.textContent;
      button.textContent = "Deleting...";

      try {
        const res = await fetch("/admin_delete_user", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: userId })
        });
        const data = await res.json();
        if (data.status === "success") {
          row.remove();
        } else {
          alert(data.message || "Failed to delete user.");
          button.textContent = originalText;
          button.disabled = false;
        }
      } catch (err) {
        alert("Error connecting to server.");
        button.textContent = originalText;
        button.disabled = false;
        console.error(err);
      }
    });
  });
});

document.querySelectorAll(".modal").forEach(modal => {
  modal.addEventListener("show.bs.modal", () => {
    document.body.classList.add("modal-open");
  });

  modal.addEventListener("hidden.bs.modal", () => {
    document.body.classList.remove("modal-open");
  });
});
