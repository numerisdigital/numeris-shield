(function () {
	"use strict";

	var app = document.getElementById("ns-2fa-app");
	if (!app) {
		return;
	}
	var userId = app.getAttribute("data-user-id");
	var panel = document.getElementById("ns-2fa-panel");

	function post(action, extra) {
		var data = new FormData();
		data.set("action", action);
		data.set("nonce", nsTwoFactor.nonce);
		data.set("user_id", userId);
		if (extra) {
			Object.keys(extra).forEach(function (k) {
				data.set(k, extra[k]);
			});
		}
		return fetch(nsTwoFactor.ajaxUrl, { method: "POST", credentials: "same-origin", body: data }).then(function (r) {
			return r.json();
		});
	}

	function showError(message) {
		var el = document.createElement("p");
		el.style.color = "#d63638";
		el.textContent = message || nsTwoFactor.i18n.genericError;
		panel.appendChild(el);
	}

	function renderBackupCodes(codes) {
		var box = document.createElement("div");
		box.className = "ns-card";
		box.style.marginTop = "16px";

		var heading = document.createElement("p");
		heading.innerHTML = "<strong>Save these backup codes somewhere safe — each one works once, and this is the only time they'll be shown.</strong>";
		box.appendChild(heading);

		var grid = document.createElement("div");
		grid.style.cssText = "display:grid;grid-template-columns:repeat(2,1fr);gap:8px;font-family:monospace;font-size:14px;margin:12px 0;";
		codes.forEach(function (code) {
			var span = document.createElement("span");
			span.textContent = code;
			grid.appendChild(span);
		});
		box.appendChild(grid);

		var doneBtn = document.createElement("button");
		doneBtn.type = "button";
		doneBtn.className = "button button-primary";
		doneBtn.textContent = "Done";
		doneBtn.addEventListener("click", function () {
			window.location.reload();
		});
		box.appendChild(doneBtn);

		panel.innerHTML = "";
		panel.appendChild(box);
	}

	function renderSetupStep(result) {
		panel.innerHTML = "";
		var box = document.createElement("div");
		box.className = "ns-card";
		box.style.marginTop = "16px";
		box.innerHTML =
			'<p>Scan this with Google Authenticator, Authy, 1Password, or similar:</p>' +
			'<div style="display:inline-block;padding:12px;background:#fff;border:1px solid #ddd;border-radius:6px;">' + result.qr_svg + "</div>" +
			'<p style="font-family:monospace;font-size:13px;background:#f5f5f5;padding:8px;border-radius:4px;display:inline-block;margin-top:12px;">' +
			result.manual_key +
			"</p>" +
			'<p class="description">Or open directly on this device: <a href="' + result.otpauth_uri + '">' + result.otpauth_uri + "</a></p>" +
			'<p><label for="ns-2fa-confirm-code"><strong>Enter the 6-digit code from your app to confirm:</strong></label><br>' +
			'<input type="text" id="ns-2fa-confirm-code" class="regular-text" autocomplete="one-time-code" size="10"></p>' +
			'<button type="button" class="button button-primary" id="ns-2fa-confirm-btn">Confirm &amp; Enable</button>' +
			'<div id="ns-2fa-confirm-error"></div>';
		panel.appendChild(box);

		document.getElementById("ns-2fa-confirm-btn").addEventListener("click", function () {
			var code = document.getElementById("ns-2fa-confirm-code").value.trim();
			var errorBox = document.getElementById("ns-2fa-confirm-error");
			errorBox.innerHTML = "";
			post("ns_2fa_confirm_setup", { code: code }).then(function (res) {
				if (res.success) {
					renderBackupCodes(res.data.backup_codes);
				} else {
					var p = document.createElement("p");
					p.style.color = "#d63638";
					p.textContent = (res.data && res.data.message) || nsTwoFactor.i18n.genericError;
					errorBox.appendChild(p);
				}
			});
		});
	}

	var startBtn = document.getElementById("ns-2fa-start");
	if (startBtn) {
		startBtn.addEventListener("click", function () {
			startBtn.disabled = true;
			post("ns_2fa_start_setup").then(function (res) {
				startBtn.disabled = false;
				if (res.success) {
					renderSetupStep(res.data);
				} else {
					showError(res.data && res.data.message);
				}
			});
		});
	}

	var regenBtn = document.getElementById("ns-2fa-regenerate-codes");
	if (regenBtn) {
		regenBtn.addEventListener("click", function () {
			if (!window.confirm(nsTwoFactor.i18n.confirmRegen)) {
				return;
			}
			post("ns_2fa_regenerate_backup_codes").then(function (res) {
				panel.innerHTML = "";
				if (res.success) {
					renderBackupCodes(res.data.backup_codes);
				} else {
					showError(res.data && res.data.message);
				}
			});
		});
	}

	var disableBtn = document.getElementById("ns-2fa-disable");
	if (disableBtn) {
		disableBtn.addEventListener("click", function () {
			var password = window.prompt(nsTwoFactor.i18n.enterPassword);
			if (password === null) {
				return;
			}
			post("ns_2fa_disable", { password: password }).then(function (res) {
				if (res.success) {
					window.location.reload();
				} else {
					panel.innerHTML = "";
					showError(res.data && res.data.message);
				}
			});
		});
	}
})();
