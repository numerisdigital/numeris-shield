<?php
/**
 * Plugin Name:       Numeris Shield
 * Plugin URI:        https://numeris.digital
 * Description:       Login hardening, brute-force protection, two-factor authentication, core hardening and activity logging for WordPress — built for reuse across Numeris Digital client sites.
 * Version:           1.1.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Numeris Digital
 * Author URI:        https://numeris.digital
 * License:           GPL-2.0+
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       numeris-shield
 * Domain Path:       /languages
 */

defined( 'ABSPATH' ) || exit;

/*
 * Recovery kill-switch: if a site owner ever gets locked out (e.g. they
 * forget a custom login slug), setting this constant in wp-config.php
 * restores 100% default WordPress login/admin behaviour, bypassing every
 * Numeris Shield hook that could interfere with reaching wp-admin. It is
 * checked at the top of every feature class before any hooks are added.
 *
 *     define( 'NUMERIS_SHIELD_DISABLE', true );
 */
if ( ! defined( 'NUMERIS_SHIELD_DISABLE' ) ) {
	define( 'NUMERIS_SHIELD_DISABLE', false );
}

define( 'NS_VERSION', '1.1.0' );
define( 'NS_DB_VERSION', '1' ); // Bump when custom table schemas change; NS_DB::maybe_upgrade() reacts to this.
define( 'NS_FILE', __FILE__ );
define( 'NS_DIR', plugin_dir_path( __FILE__ ) );
define( 'NS_URL', plugin_dir_url( __FILE__ ) );
define( 'NS_TEXTDOMAIN', 'numeris-shield' );

require NS_DIR . 'includes/class-ns-db.php';
require NS_DIR . 'includes/class-ns-settings.php';
require NS_DIR . 'includes/class-ns-login-shield.php';
require NS_DIR . 'includes/class-ns-brute-force.php';
require NS_DIR . 'includes/vendor/class-ns-qr-encoder.php';
require NS_DIR . 'includes/class-ns-totp.php';
require NS_DIR . 'includes/class-ns-two-factor.php';
require NS_DIR . 'includes/class-ns-hardening.php';
require NS_DIR . 'includes/class-ns-activity-log.php';
require NS_DIR . 'includes/class-ns-environment-indicator.php';
require NS_DIR . 'includes/class-ns-github-updater.php';
require NS_DIR . 'includes/class-ns-plugin.php';
require NS_DIR . 'admin/class-ns-admin-page.php';
require NS_DIR . 'admin/class-ns-log-page.php';

register_activation_hook( NS_FILE, array( 'NS_DB', 'activate' ) );
register_deactivation_hook( NS_FILE, array( 'NS_Plugin', 'deactivate' ) );
// Uninstall is handled by uninstall.php (the standard WP mechanism), which
// respects the "keep data on uninstall" setting before dropping any tables.

NS_Plugin::instance();
