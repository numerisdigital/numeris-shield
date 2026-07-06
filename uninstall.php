<?php
/**
 * Uninstall handler.
 *
 * WordPress runs this file standalone — it does NOT load the main plugin
 * file first, specifically so a plugin's normal runtime hooks never fire
 * during uninstall. That means none of the NS_* constants from
 * numeris-shield.php exist here; the class files below are required by
 * direct relative path instead, and are written so they don't depend on
 * those constants either.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once __DIR__ . '/includes/class-ns-settings.php';
require_once __DIR__ . '/includes/class-ns-db.php';

$options   = get_option( NS_Settings::OPTION_KEY, array() );
$keep_data = array_key_exists( 'keep_data_on_uninstall', $options )
	? (bool) $options['keep_data_on_uninstall']
	: true; // Default on — never destroy data on uninstall unless the site owner explicitly opted out.

if ( ! $keep_data ) {
	delete_option( NS_Settings::OPTION_KEY );
	delete_option( 'ns_db_version' );
	NS_DB::drop_tables();

	// Feature 3 (two-factor auth) will store per-user secrets/backup codes
	// in user meta rather than a custom table; when that's implemented,
	// its cleanup (delete_metadata('user', 0, '_ns_...', '', true)) belongs
	// here too, gated behind this same $keep_data check.
}
