<?php
/**
 * Feature 5: Activity Logging + Alerts.
 *
 * Every event is written with a ready-to-read message (not just a raw
 * event_type code) so the admin log viewer never needs to reconstruct
 * meaning from machine-readable fields — the human-readable sentence is
 * generated once, here, at the moment we actually know the full context
 * (who, what, before/after), rather than guessed at display time.
 */

defined( 'ABSPATH' ) || exit;

class NS_Activity_Log {

	const CRON_HOOK = 'ns_prune_activity_log';

	public function __construct() {
		if ( NUMERIS_SHIELD_DISABLE ) {
			return;
		}

		add_action( 'wp_login', array( $this, 'log_login_success' ), 20, 2 );
		add_action( 'wp_login_failed', array( $this, 'log_login_failed' ), 20, 2 );
		add_action( 'ns_lockout_triggered', array( $this, 'log_lockout' ), 10, 3 );
		add_action( 'ns_lockout_triggered', array( $this, 'maybe_alert_lockout' ), 20, 3 );
		add_action( 'set_user_role', array( $this, 'log_role_change' ), 10, 3 );
		add_action( 'set_user_role', array( $this, 'maybe_alert_promoted_to_admin' ), 20, 3 );
		add_action( 'user_register', array( $this, 'log_user_registered' ) );
		add_action( 'user_register', array( $this, 'maybe_alert_new_admin' ), 20 );
		add_action( 'activated_plugin', array( $this, 'log_plugin_activated' ) );
		add_action( 'switch_theme', array( $this, 'log_theme_activated' ) );
		add_action( 'load-theme-editor.php', array( $this, 'log_file_editor_use' ) );
		add_action( 'load-plugin-editor.php', array( $this, 'log_file_editor_use' ) );
		add_action( 'ns_2fa_enabled', array( $this, 'log_2fa_enabled' ) );
		add_action( 'ns_2fa_disabled', array( $this, 'log_2fa_disabled' ) );
		add_action( 'ns_2fa_disabled', array( $this, 'maybe_alert_2fa_disabled' ), 20 );

		add_action( self::CRON_HOOK, array( $this, 'prune_old_logs' ) );
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::CRON_HOOK );
		}
	}

	/* ── Event logging ────────────────────────────────────────────────── */

	public function log_login_success( $user_login, $user ) {
		$this->insert(
			'login_success',
			'info',
			sprintf( __( 'Successful login for "%s"', 'numeris-shield' ), $user_login ),
			array(),
			$user->ID,
			$user_login
		);
	}

	public function log_login_failed( $username, $error = null ) {
		// A lockout-blocked attempt already gets its own, more informative
		// 'lockout_triggered'/repeat-attempt-while-locked entry — logging
		// every one of those as a separate generic "login failed" line too
		// would just be noise on top of the log entry that actually matters.
		if ( $error instanceof WP_Error && NS_Brute_Force::ERROR_CODE === $error->get_error_code() ) {
			return;
		}
		$this->insert(
			'login_fail',
			'warning',
			sprintf( __( 'Failed login attempt for "%s"', 'numeris-shield' ), $username ),
			array(),
			null,
			$username
		);
	}

	public function log_lockout( $identifier, $type, $duration_minutes ) {
		$message = ( 'ip' === $type )
			? sprintf( __( 'IP address %1$s locked out for %2$d minutes after repeated failed logins', 'numeris-shield' ), $identifier, $duration_minutes )
			: sprintf( __( 'Username "%1$s" locked out for %2$d minutes after repeated failed logins', 'numeris-shield' ), $identifier, $duration_minutes );

		$this->insert( 'lockout_triggered', 'critical', $message, compact( 'identifier', 'type', 'duration_minutes' ) );
	}

	public function log_role_change( $user_id, $role, $old_roles ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$editor      = wp_get_current_user();
		$role_names  = function_exists( 'wp_roles' ) ? wp_roles()->get_names() : array();
		$new_label   = $role_names[ $role ] ?? $role;
		$old_label   = ! empty( $old_roles ) ? ( $role_names[ $old_roles[0] ] ?? $old_roles[0] ) : __( 'no role', 'numeris-shield' );
		$severity    = ( 'administrator' === $role && ! in_array( 'administrator', (array) $old_roles, true ) ) ? 'warning' : 'info';

		$message = sprintf(
			/* translators: 1: username, 2: old role, 3: new role, 4: who made the change */
			__( 'Role changed for "%1$s": %2$s → %3$s (changed by "%4$s")', 'numeris-shield' ),
			$user->user_login,
			$old_label,
			$new_label,
			$editor && $editor->exists() ? $editor->user_login : __( 'system', 'numeris-shield' )
		);

		$this->insert( 'role_changed', $severity, $message, compact( 'role', 'old_roles' ), $user_id, $user->user_login );
	}

	public function log_user_registered( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$this->insert(
			'user_registered',
			'info',
			sprintf( __( 'New user account created: "%s"', 'numeris-shield' ), $user->user_login ),
			array(),
			$user_id,
			$user->user_login
		);
	}

	public function log_plugin_activated( $plugin ) {
		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin, false, false );
		$name = ! empty( $data['Name'] ) ? $data['Name'] : $plugin;
		$this->insert( 'plugin_activated', 'info', sprintf( __( 'Plugin activated: %s', 'numeris-shield' ), $name ), compact( 'plugin' ) );
	}

	public function log_theme_activated( $new_name ) {
		$this->insert( 'theme_activated', 'info', sprintf( __( 'Theme activated: %s', 'numeris-shield' ), $new_name ) );
	}

	/**
	 * Should be effectively unreachable once Feature 4's disable_file_editor
	 * setting is on (it revokes the underlying capability, not just the
	 * menu item) — this exists for the case that setting is off, or a
	 * differently-configured site still allows the editor. A hit here is
	 * inherently notable, hence 'critical'.
	 */
	public function log_file_editor_use() {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) || 'update' !== ( $_POST['action'] ?? '' ) ) {
			return;
		}
		$file = sanitize_text_field( wp_unslash( $_POST['file'] ?? $_POST['theme'] ?? $_POST['plugin'] ?? 'unknown file' ) );
		$this->insert( 'file_editor_used', 'critical', sprintf( __( 'Theme/plugin file editor was used to save: %s', 'numeris-shield' ), $file ) );
	}

	public function log_2fa_enabled( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$this->insert(
			'2fa_enabled',
			'info',
			sprintf( __( 'Two-factor authentication enabled for "%s"', 'numeris-shield' ), $user->user_login ),
			array(),
			$user_id,
			$user->user_login
		);
	}

	public function log_2fa_disabled( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$this->insert(
			'2fa_disabled',
			'warning',
			sprintf( __( 'Two-factor authentication disabled for "%s"', 'numeris-shield' ), $user->user_login ),
			array(),
			$user_id,
			$user->user_login
		);
	}

	/* ── Alerts ───────────────────────────────────────────────────────── */

	public function maybe_alert_lockout( $identifier, $type, $duration_minutes ) {
		if ( ! NS_Settings::get( 'alert_on_lockout' ) ) {
			return;
		}
		$subject = sprintf( '[%s] Lockout triggered', get_bloginfo( 'name' ) );
		$body    = ( 'ip' === $type )
			? sprintf( "IP address %s was locked out for %d minutes after repeated failed login attempts on %s.", $identifier, $duration_minutes, home_url() )
			: sprintf( "Username \"%s\" was locked out for %d minutes after repeated failed login attempts on %s.", $identifier, $duration_minutes, home_url() );
		wp_mail( NS_Settings::alert_email(), $subject, $body );
	}

	public function maybe_alert_new_admin( $user_id ) {
		if ( ! NS_Settings::get( 'alert_on_new_admin' ) ) {
			return;
		}
		$user = get_userdata( $user_id );
		if ( ! $user || ! in_array( 'administrator', (array) $user->roles, true ) ) {
			return;
		}
		$subject = sprintf( '[%s] New administrator account created', get_bloginfo( 'name' ) );
		$body    = sprintf(
			"A new administrator account was just created on %s:\n\nUsername: %s\nEmail: %s\n\nIf you didn't expect this, investigate immediately.",
			home_url(),
			$user->user_login,
			$user->user_email
		);
		wp_mail( NS_Settings::alert_email(), $subject, $body );
	}

	public function maybe_alert_promoted_to_admin( $user_id, $role, $old_roles ) {
		if ( 'administrator' !== $role || in_array( 'administrator', (array) $old_roles, true ) ) {
			return; // Not a new elevation to admin — either a different role, or already was one.
		}
		if ( ! NS_Settings::get( 'alert_on_new_admin' ) ) {
			return;
		}
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$subject = sprintf( '[%s] User promoted to administrator', get_bloginfo( 'name' ) );
		$body    = sprintf(
			"The account \"%s\" was just given administrator access on %s.\n\nIf you didn't expect this, investigate immediately.",
			$user->user_login,
			home_url()
		);
		wp_mail( NS_Settings::alert_email(), $subject, $body );
	}

	public function maybe_alert_2fa_disabled( $user_id ) {
		if ( ! NS_Settings::get( 'alert_on_2fa_disabled' ) ) {
			return;
		}
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$subject = sprintf( '[%s] Two-factor authentication disabled', get_bloginfo( 'name' ) );
		$body    = sprintf(
			"Two-factor authentication was just disabled for the account \"%s\" on %s.\n\nIf you didn't expect this, investigate immediately.",
			$user->user_login,
			home_url()
		);
		wp_mail( NS_Settings::alert_email(), $subject, $body );
	}

	/* ── Pruning ──────────────────────────────────────────────────────── */

	public function prune_old_logs() {
		global $wpdb;
		$days  = max( 1, (int) NS_Settings::get( 'log_retention_days' ) );
		$table = NS_DB::log_table();
		$wpdb->query( $wpdb->prepare(
			"DELETE FROM {$table} WHERE created_at < %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name only, value is prepared
			gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) )
		) );
	}

	/* ── Helpers ──────────────────────────────────────────────────────── */

	private function insert( $event_type, $severity, $message, $context = array(), $user_id = null, $username = null ) {
		global $wpdb;
		$wpdb->insert(
			NS_DB::log_table(),
			array(
				'event_type' => $event_type,
				'severity'   => $severity,
				'user_id'    => $user_id,
				'username'   => $username,
				'ip_address' => $this->get_client_ip(),
				'message'    => $message,
				'context'    => wp_json_encode( $context ),
				'created_at' => current_time( 'mysql', true ),
			),
			array( '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	private function get_client_ip() {
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}
}
