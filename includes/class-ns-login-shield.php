<?php
/**
 * Feature 1: Custom Login URL.
 *
 * Moves the login form to a site-owner-chosen slug and returns a plain 404
 * (never a redirect) for direct hits on wp-login.php or wp-admin while
 * logged out — a redirect would confirm "yes, there's a login here, it's
 * just been moved", which defeats the point against automated scanners
 * that follow redirects looking for exactly that.
 *
 * Hook timing matters a lot here: is_user_logged_in() and wp_get_current_user()
 * are pluggable functions that WordPress doesn't load until *after*
 * 'plugins_loaded' fires (specifically so plugins get a chance to override
 * them first). Calling them from a 'plugins_loaded' callback would fatal
 * error with "call to undefined function". 'init' is the earliest hook
 * where they're guaranteed to exist — and it still fires before wp-admin's
 * own auth-redirect logic runs, since that logic lives in wp-admin/admin.php
 * *after* its `require wp-load.php` line, and wp-load.php's own bootstrap
 * is what fires 'init' in the first place.
 */

defined( 'ABSPATH' ) || exit;

class NS_Login_Shield {

	/** @var string */
	private $slug = '';

	public function __construct() {
		// Recovery kill-switch — see numeris-shield.php for how this is set.
		// Checked first and unconditionally: if present, this class does
		// nothing at all, guaranteeing normal wp-login.php/wp-admin access
		// no matter what's saved in the plugin's settings.
		if ( NUMERIS_SHIELD_DISABLE ) {
			return;
		}

		if ( ! NS_Settings::get( 'login_shield_enabled' ) ) {
			return;
		}

		$slug = NS_Settings::get( 'login_slug' );
		if ( '' === $slug ) {
			// Matches the safety net in NS_Settings::sanitize() — belt and
			// braces against the setting ever being enabled with no slug.
			return;
		}
		$this->slug = $slug;

		// Rewriting site_url()/network_site_url() output is what makes
		// password-reset emails, the logout link, and the login form's own
		// action= attribute all keep working: every one of those is built
		// by core calling site_url('wp-login.php...') or
		// network_site_url('wp-login.php...') rather than hardcoding a URL,
		// so rewriting the two filters covers every case in one place.
		// These are plain string filters with no pluggable-function
		// dependency, so they're safe to register immediately.
		add_filter( 'site_url', array( $this, 'rewrite_login_url' ), 10, 2 );
		add_filter( 'network_site_url', array( $this, 'rewrite_login_url' ), 10, 2 );

		add_action( 'init', array( $this, 'handle_request' ), 1 );
	}

	/**
	 * Rewrites any generated "...wp-login.php..." URL to use the custom
	 * slug instead, preserving whatever query string/action was appended
	 * (e.g. ?action=logout&_wpnonce=..., ?action=rp&key=...&login=...).
	 */
	public function rewrite_login_url( $url ) {
		if ( false !== strpos( $url, 'wp-login.php' ) ) {
			$url = str_replace( 'wp-login.php', $this->slug, $url );
		}
		return $url;
	}

	/**
	 * The single entry point, hooked on 'init'. Three possible outcomes:
	 *  - request matches the custom slug         -> serve the real login page
	 *  - request is a direct hit on wp-login.php  -> 404
	 *  - request is wp-admin/* and logged out     -> 404
	 * Anything else (including the REST API, admin-ajax.php, admin-post.php,
	 * and every normal front-end URL) is untouched — the path matching
	 * below is specific enough that nothing else can ever match it, so
	 * there's no separate "is this a REST request?" check needed.
	 */
	public function handle_request() {
		$relative = $this->get_relative_path();

		if ( $relative === $this->slug ) {
			$this->serve_login_page();
			return;
		}

		if ( 'wp-login.php' === $relative ) {
			// Always 404, regardless of login state. Every legitimate
			// internal link to wp-login.php has already been rewritten to
			// the custom slug by rewrite_login_url() above, so a real hit
			// here only ever comes from an old bookmark, a scanner, or
			// someone guessing — none of which should get any information.
			$this->send_404();
			return;
		}

		if ( $this->is_shielded_admin_path( $relative ) && ! is_user_logged_in() ) {
			$this->send_404();
			return;
		}

		// Any other path (front-end pages, assets, wp-json, admin-ajax.php,
		// admin-post.php, an already-authenticated wp-admin visit) falls
		// through here untouched and continues exactly as WordPress would
		// normally handle it.
	}

	/**
	 * True for any /wp-admin/... path except the two entry points that
	 * logged-out visitors legitimately need: admin-ajax.php (frontend AJAX
	 * of every kind — search, cart, form widgets, etc. all use this) and
	 * admin-post.php (the standard way themes/plugins handle logged-out
	 * form submissions — including this very site's own contact forms).
	 */
	private function is_shielded_admin_path( $relative ) {
		if ( 'wp-admin' !== $relative && 0 !== strpos( $relative, 'wp-admin/' ) ) {
			return false;
		}

		$always_allowed = array( 'wp-admin/admin-ajax.php', 'wp-admin/admin-post.php' );
		return ! in_array( $relative, $always_allowed, true );
	}

	/**
	 * Serves the real wp-login.php in place, so the browser's address bar
	 * keeps showing the custom slug instead of a redirect to wp-login.php.
	 * wp-login.php's own top-of-file `require wp-load.php` becomes a no-op
	 * here (WordPress is already fully bootstrapped, and PHP's require_once
	 * dedupes by resolved path) — execution just continues straight into
	 * wp-login.php's actual login-form/action-switch logic.
	 */
	private function serve_login_page() {
		global $pagenow, $user_login, $error;

		$pagenow = 'wp-login.php';

		// wp-login.php normally runs as a true top-level script, where a
		// bare `$user_login`/`$error` reference resolves to the global
		// scope automatically. Here it's include()'d from inside a class
		// method instead, so PHP resolves those same bare references
		// against *this method's* local scope unless we explicitly bind
		// them to globals first — otherwise PHP 8's "Undefined variable"
		// warnings get printed straight into the page (and, with
		// display_errors on, right into the username field's value
		// attribute, breaking the form's HTML).
		if ( ! isset( $user_login ) ) {
			$user_login = '';
		}
		if ( ! isset( $error ) ) {
			$error = false;
		}

		require ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * A plain, generic 404 — deliberately not the active theme's own
	 * 404.php template. This plugin is reused across client sites running
	 * themes we don't control, and a theme's 404 template can assume things
	 * (like the main WP_Query having actually run its 404 branch) that
	 * aren't true this early in the request — safer to keep this
	 * dependency-free than to risk a fatal error on someone else's theme.
	 */
	private function send_404() {
		status_header( 404 );
		nocache_headers();
		wp_die(
			esc_html__( 'Not Found', 'numeris-shield' ),
			'',
			array( 'response' => 404 )
		);
	}

	/**
	 * The request path relative to the site's own install path, with
	 * leading/trailing slashes trimmed — e.g. "wp-admin/edit.php",
	 * "wp-login.php", or a custom slug like "secure-access". Handles sites
	 * installed in a subdirectory (home_url() not at the domain root).
	 */
	private function get_relative_path() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path        = (string) parse_url( $request_uri, PHP_URL_PATH );

		$home_path = (string) parse_url( home_url( '/' ), PHP_URL_PATH );
		$home_path = rtrim( $home_path, '/' );

		if ( '' !== $home_path && 0 === strpos( $path, $home_path ) ) {
			$path = substr( $path, strlen( $home_path ) );
		}

		return trim( $path, '/' );
	}
}
