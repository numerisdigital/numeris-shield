<?php
/**
 * Feature 4: Core Hardening.
 *
 * Five independent, individually-toggleable measures. Each one guards
 * itself with its own setting check, so turning one off never disables
 * another.
 */

defined( 'ABSPATH' ) || exit;

class NS_Hardening {

	public function __construct() {
		if ( NUMERIS_SHIELD_DISABLE ) {
			return;
		}

		if ( NS_Settings::get( 'disable_xmlrpc' ) ) {
			$this->disable_xmlrpc();
		}
		if ( NS_Settings::get( 'block_user_enumeration' ) ) {
			$this->block_user_enumeration();
		}
		if ( NS_Settings::get( 'hide_wp_version' ) ) {
			$this->hide_wp_version();
		}
		if ( NS_Settings::get( 'disable_file_editor' ) ) {
			$this->disable_file_editor();
		}
		if ( NS_Settings::get( 'security_headers_enabled' ) ) {
			// init at priority 0 is the primary mechanism — it's the
			// earliest hook that fires in every context (front end, admin,
			// login, and a request NS_Login_Shield is about to 404), so
			// headers land even on responses that exit before send_headers/
			// admin_init would otherwise get a chance to fire (confirmed by
			// testing: a logged-out /wp-admin/ hit is blocked with a 404 by
			// Login Shield's own init-priority-1 hook, which runs — and
			// exits — before admin_init ever fires for that request).
			// send_headers/login_init/admin_init are kept too, redundant
			// but harmless, as a defence-in-depth fallback.
			add_action( 'init', array( $this, 'send_security_headers' ), 0 );
			add_action( 'send_headers', array( $this, 'send_security_headers' ) );
			add_action( 'login_init', array( $this, 'send_security_headers' ) );
			add_action( 'admin_init', array( $this, 'send_security_headers' ) );
		}
	}

	/**
	 * Belt and braces: the xmlrpc_enabled filter stops WordPress's own
	 * XML-RPC methods from doing anything, but xmlrpc.php would still
	 * respond (with a "services are disabled" fault) rather than being
	 * genuinely unreachable — so a direct 403 on the request itself is
	 * added too. Also strips the auto-discovery links and X-Pingback
	 * header that advertise the endpoint exists in the first place.
	 */
	private function disable_xmlrpc() {
		add_filter( 'xmlrpc_enabled', '__return_false' );
		remove_action( 'wp_head', 'rsd_link' );
		remove_action( 'wp_head', 'wlwmanifest_link' );

		add_filter( 'wp_headers', function ( $headers ) {
			unset( $headers['X-Pingback'] );
			return $headers;
		} );

		add_action( 'init', function () {
			if ( false !== strpos( $_SERVER['REQUEST_URI'] ?? '', 'xmlrpc.php' ) ) {
				status_header( 403 );
				nocache_headers();
				wp_die( esc_html__( 'XML-RPC is disabled on this site.', 'numeris-shield' ), '', array( 'response' => 403 ) );
			}
		}, 1 );
	}

	/**
	 * Two distinct enumeration vectors, both blocked:
	 *  - ?author=N on the front end, which WordPress's own canonical
	 *    redirect turns into /author/{username}/ — revealing the username
	 *    from nothing but a guessed number, even if author archives are
	 *    never linked anywhere.
	 *  - the REST API's /wp/v2/users endpoints, which list every user who
	 *    has authored a post (username, display name, avatar) to *any*
	 *    unauthenticated request by default.
	 */
	private function block_user_enumeration() {
		add_action( 'init', function () {
			if ( is_admin() ) {
				return;
			}
			$author_param = $_GET['author'] ?? null;
			if ( null !== $author_param && is_numeric( $author_param ) ) {
				wp_safe_redirect( home_url( '/' ), 301 );
				exit;
			}
		} );

		add_filter( 'rest_endpoints', function ( $endpoints ) {
			if ( ! is_user_logged_in() ) {
				unset( $endpoints['/wp/v2/users'] );
				unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
			}
			return $endpoints;
		} );
	}

	/**
	 * Removes the version number from three places it normally leaks:
	 * the <meta name="generator"> tag, the <generator> element in RSS/Atom
	 * feeds, and the ?ver=X.Y.Z query string WordPress appends to its own
	 * enqueued scripts/styles (which otherwise discloses the exact core
	 * version to anyone viewing page source, letting an attacker target
	 * known vulnerabilities for that specific version).
	 */
	private function hide_wp_version() {
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );

		add_filter( 'style_loader_src', array( $this, 'strip_ver_query_arg' ) );
		add_filter( 'script_loader_src', array( $this, 'strip_ver_query_arg' ) );
	}

	/**
	 * Removes only the "ver" query parameter from an enqueued asset URL,
	 * without going through WordPress's remove_query_arg(). That helper
	 * round-trips the query string through parse_str(), which silently
	 * collapses repeated query keys down to the last occurrence — and
	 * third-party URLs this filter also sees (e.g. Google Fonts's
	 * family=A&family=B) rely on repeating a key on purpose. Operating on
	 * the raw "key=value" pairs instead leaves every other pair, including
	 * duplicates, untouched.
	 */
	public function strip_ver_query_arg( $src ) {
		$query_pos = strpos( $src, '?' );
		if ( false === $query_pos ) {
			return $src;
		}

		$base  = substr( $src, 0, $query_pos );
		$query = substr( $src, $query_pos + 1 );

		$fragment = '';
		$hash_pos = strpos( $query, '#' );
		if ( false !== $hash_pos ) {
			$fragment = substr( $query, $hash_pos );
			$query    = substr( $query, 0, $hash_pos );
		}

		$pairs = array_filter( explode( '&', $query ), function ( $pair ) {
			return '' !== $pair && 'ver' !== $pair && 0 !== strpos( $pair, 'ver=' );
		} );

		$query = implode( '&', $pairs );

		return $base . ( '' !== $query ? '?' . $query : '' ) . $fragment;
	}

	/**
	 * DISALLOW_FILE_EDIT is normally set in wp-config.php, but defining it
	 * here — before admin_menu fires, since plugins are all loaded well
	 * ahead of that — works just as well: WordPress's own map_meta_cap()
	 * revokes the edit_themes/edit_plugins/edit_files capabilities
	 * entirely once this constant is true, which is what actually blocks
	 * direct access to theme-editor.php/plugin-editor.php, not just the
	 * menu items being hidden.
	 */
	private function disable_file_editor() {
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}
	}

	/**
	 * Hooked on send_headers (front end), login_init (wp-login.php doesn't
	 * go through the front-end query at all) and admin_init (wp-admin) —
	 * between them, every context gets these headers.
	 */
	public function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
	}
}
