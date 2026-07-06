<?php
/**
 * Custom table schema + lifecycle management.
 *
 * All three tables are created on activation (even though only some
 * features are implemented yet) so later features never need a
 * "did you deactivate/reactivate?" migration step — NS_DB::maybe_upgrade()
 * re-runs dbDelta() automatically whenever NS_DB_VERSION is bumped.
 *
 * Why custom tables instead of wp_options: attempt/log rows are numerous,
 * queried by time range and identifier, and never need to be autoloaded
 * on every page load — storing them as options would bloat the alloptions
 * cache that WordPress loads on every single request.
 */

defined( 'ABSPATH' ) || exit;

class NS_DB {

	public static function attempts_table() {
		global $wpdb;
		return $wpdb->prefix . 'ns_login_attempts';
	}

	public static function lockouts_table() {
		global $wpdb;
		return $wpdb->prefix . 'ns_lockouts';
	}

	public static function log_table() {
		global $wpdb;
		return $wpdb->prefix . 'ns_activity_log';
	}

	/**
	 * Runs on plugin activation. Creates/updates all custom tables and
	 * seeds default settings the first time the plugin is ever activated.
	 */
	public static function activate() {
		self::create_tables();
		update_option( 'ns_db_version', NS_DB_VERSION );

		if ( class_exists( 'NS_Settings' ) ) {
			NS_Settings::maybe_set_defaults();
		}
	}

	/**
	 * Called on every admin load; only actually touches the database when
	 * the stored schema version is behind NS_DB_VERSION, so this is cheap
	 * on every normal request.
	 */
	public static function maybe_upgrade() {
		if ( get_option( 'ns_db_version' ) !== NS_DB_VERSION ) {
			self::create_tables();
			update_option( 'ns_db_version', NS_DB_VERSION );
		}
	}

	private static function create_tables() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();

		// Raw record of every login attempt, used to count recent failures
		// within a rolling window per IP and per username.
		$attempts = self::attempts_table();
		dbDelta( "CREATE TABLE {$attempts} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			ip_address VARCHAR(45) NOT NULL,
			username VARCHAR(60) NOT NULL DEFAULT '',
			success TINYINT(1) NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL,
			PRIMARY KEY  (id),
			KEY ip_address (ip_address),
			KEY username (username),
			KEY created_at (created_at)
		) {$charset_collate};" );

		// Current lockout state per identifier (an IP or a username can each
		// be locked independently). offense_count drives exponential backoff:
		// each new lockout for the same identifier multiplies the duration.
		$lockouts = self::lockouts_table();
		dbDelta( "CREATE TABLE {$lockouts} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			identifier VARCHAR(191) NOT NULL,
			identifier_type VARCHAR(20) NOT NULL,
			fail_count INT UNSIGNED NOT NULL DEFAULT 0,
			offense_count INT UNSIGNED NOT NULL DEFAULT 0,
			locked_until DATETIME NULL,
			updated_at DATETIME NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY identifier_combo (identifier, identifier_type)
		) {$charset_collate};" );

		// Append-only activity log, queried most-recent-first with pagination
		// in the admin UI and pruned by the retention setting via WP-Cron.
		$log = self::log_table();
		dbDelta( "CREATE TABLE {$log} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			event_type VARCHAR(50) NOT NULL,
			severity VARCHAR(20) NOT NULL DEFAULT 'info',
			user_id BIGINT UNSIGNED NULL,
			username VARCHAR(60) NULL,
			ip_address VARCHAR(45) NULL,
			message TEXT NULL,
			context LONGTEXT NULL,
			created_at DATETIME NOT NULL,
			PRIMARY KEY  (id),
			KEY event_type (event_type),
			KEY created_at (created_at),
			KEY user_id (user_id)
		) {$charset_collate};" );
	}

	/**
	 * Drops all custom tables. Only ever called from uninstall.php, and only
	 * when the "keep data on uninstall" setting is off.
	 */
	public static function drop_tables() {
		global $wpdb;
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::attempts_table() ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name only, no user input
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::lockouts_table() ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::log_table() ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
	}
}
