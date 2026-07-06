(function () {
	"use strict";

	// Progressive enhancement: every tab is a real link to ?tab=X (so it
	// works with JS disabled, via a full page reload), but when JS is
	// available we switch instantly client-side instead and just update
	// the URL for bookmarkability.
	var tabs = document.querySelectorAll(".ns-tab");
	var panels = document.querySelectorAll(".ns-tab-panel");

	if (!tabs.length || !panels.length) {
		return;
	}

	tabs.forEach(function (tab) {
		tab.addEventListener("click", function (e) {
			e.preventDefault();
			var target = tab.getAttribute("data-tab");

			tabs.forEach(function (t) {
				t.classList.toggle("is-active", t === tab);
			});
			panels.forEach(function (panel) {
				panel.hidden = panel.getAttribute("data-tab") !== target;
			});

			if (window.history && window.history.pushState) {
				window.history.pushState(null, "", tab.getAttribute("href"));
			}
		});
	});
})();
