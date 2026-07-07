<?php
/**
 * Plugin bootstrap: loads the text domain, keeps the DB schema current,
 * and wires up whichever feature classes exist so far. Each feature class
 * is responsible for its own "am I actually enabled?" checks internally —
 * this class just decides *when* things get instantiated, not *whether*.
 */

defined( 'ABSPATH' ) || exit;

class NS_Plugin {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'plugins_loaded', array( $this, 'load_textdomain' ) );
		add_action( 'admin_init', array( 'NS_DB', 'maybe_upgrade' ) );
		add_action( 'admin_init', array( 'NS_Settings', 'register' ) );

		// Features 1–5 — fully implemented. Each constructor checks the
		// recovery constant and its own enabled setting itself, so it's
		// always safe to instantiate unconditionally here. NS_Two_Factor,
		// NS_Hardening and NS_Activity_Log specifically need to run outside
		// is_admin() too — their hooks (login_init, send_headers, front-end
		// enumeration guards, wp_login/wp_login_failed) fire on
		// wp-login.php and the front end, not just in wp-admin.
		new NS_Login_Shield();
		new NS_Brute_Force();
		new NS_Two_Factor();
		new NS_Hardening();
		new NS_Activity_Log();
		new NS_Environment_Indicator();
		new NS_GitHub_Updater();

		if ( is_admin() ) {
			new NS_Admin_Page();
			new NS_Log_Page();
		}
	}

	public function load_textdomain() {
		load_plugin_textdomain( NS_TEXTDOMAIN, false, dirname( plugin_basename( NS_FILE ) ) . '/languages' );
	}

	/**
	 * Runs on plugin deactivation (not uninstall — see uninstall.php for
	 * that, which additionally drops the custom tables if the site owner
	 * opted out of "keep data on uninstall").
	 */
	public static function deactivate() {
		wp_clear_scheduled_hook( NS_Activity_Log::CRON_HOOK );
	}
}
