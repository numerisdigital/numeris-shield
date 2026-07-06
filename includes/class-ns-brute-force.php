<?php
/**
 * Feature 2: Brute-Force Protection.
 *
 * Tracks failed logins per IP address and/or per username in a dedicated
 * lockout state table, locking out either identifier once too many
 * failures happen in a row. Repeat offenders get exponentially longer
 * lockouts (capped), and every attempt is also written to a raw log table
 * for audit purposes.
 *
 * Security-relevant design notes, since these are easy to get subtly wrong:
 *
 * - The lockout check runs on the 'authenticate' filter at priority 30 —
 *   *after* WordPress's own username/password check (priority 20) — and
 *   unconditionally overrides whatever that check decided. Hooking earlier
 *   wouldn't actually help: WordPress's own wp_authenticate_username_password()
 *   only short-circuits on an incoming WP_Error when the username/password
 *   fields are empty, so a priority-1 WP_Error can still get silently
 *   replaced by core's own (successful!) result for a non-empty, correct
 *   password. Overriding *after* the real check guarantees a locked-out
 *   identifier can never log in, correct password or not.
 * - The error message is deliberately generic and identical whether the
 *   username doesn't exist or the password is wrong (see
 *   generic_login_error()) — WordPress's default messages differ between
 *   those two cases, which lets an attacker enumerate valid usernames
 *   just from the login form's responses.
 */

defined( 'ABSPATH' ) || exit;

class NS_Brute_Force {

	const ERROR_CODE = 'ns_locked_out';

	public function __construct() {
		if ( NUMERIS_SHIELD_DISABLE ) {
			return;
		}
		if ( ! NS_Settings::get( 'brute_force_enabled' ) ) {
			return;
		}

		add_filter( 'authenticate', array( $this, 'check_lockout' ), 30, 3 );
		add_filter( 'authenticate', array( $this, 'generic_login_error' ), 40, 1 );
		add_action( 'wp_login_failed', array( $this, 'record_failed_attempt' ), 10, 2 );
		add_action( 'wp_login', array( $this, 'record_successful_attempt' ), 10, 2 );
	}

	/**
	 * Runs after core's own authentication check. If either identifier
	 * (IP and/or username, per the lock_by_* settings) is currently locked,
	 * this replaces whatever core decided — success or failure — with a
	 * lockout error, so correct credentials still can't log in while locked.
	 */
	public function check_lockout( $user, $username, $password ) {
		unset( $password );

		$identifiers = $this->active_identifiers( $username );
		foreach ( $identifiers as $identifier ) {
			$lockout = $this->get_lockout( $identifier['value'], $identifier['type'] );
			if ( $lockout && $this->is_locked( $lockout ) ) {
				$minutes = (int) ceil( ( strtotime( $lockout->locked_until ) - time() ) / MINUTE_IN_SECONDS );
				return new WP_Error(
					self::ERROR_CODE,
					sprintf(
						/* translators: %d: minutes remaining */
						__( '<strong>Error:</strong> Too many failed login attempts. Please try again in %d minute(s).', 'numeris-shield' ),
						max( 1, $minutes )
					)
				);
			}
		}

		return $user;
	}

	/**
	 * Unifies every "wrong username" / "wrong password" / "unknown email"
	 * error from core into one message, so the login form's response can't
	 * be used to enumerate which usernames exist on the site.
	 */
	public function generic_login_error( $user ) {
		if ( ! is_wp_error( $user ) ) {
			return $user;
		}

		if ( self::ERROR_CODE === $user->get_error_code() ) {
			return $user; // Already our own generic lockout message.
		}

		$enumerable_codes = array( 'invalid_username', 'invalid_email', 'incorrect_password', 'empty_username', 'empty_password' );
		foreach ( $user->get_error_codes() as $code ) {
			if ( in_array( $code, $enumerable_codes, true ) ) {
				return new WP_Error( 'ns_generic_login_error', __( '<strong>Error:</strong> Invalid username or password.', 'numeris-shield' ) );
			}
		}

		return $user;
	}

	/**
	 * Records the failed attempt for audit purposes, and — unless this
	 * identifier is already locked out — increments its failure count,
	 * triggering a new (exponentially longer) lockout once the threshold
	 * is crossed.
	 */
	public function record_failed_attempt( $username, $error = null ) {
		global $wpdb;

		$ip = $this->get_client_ip();
		$wpdb->insert(
			NS_DB::attempts_table(),
			array(
				'ip_address' => $ip,
				'username'   => $this->normalize_username( $username ),
				'success'    => 0,
				'created_at' => current_time( 'mysql', true ),
			),
			array( '%s', '%s', '%d', '%s' )
		);

		// Don't pile more increments onto an identifier that's already
		// locked — it can't log in either way, and this avoids the fail
		// count racing ahead of what the site owner configured.
		if ( $error instanceof WP_Error && self::ERROR_CODE === $error->get_error_code() ) {
			return;
		}

		foreach ( $this->active_identifiers( $username ) as $identifier ) {
			$this->register_failure( $identifier['value'], $identifier['type'] );
		}
	}

	/**
	 * A successful login proves this identifier isn't currently an
	 * attacker — clear its failure count and any active lockout. The
	 * offense count (which drives exponential backoff) is deliberately
	 * left alone, so a shared IP that was recently attacking doesn't get a
	 * clean slate just because a legitimate user also logged in from it.
	 */
	public function record_successful_attempt( $username, $user = null ) {
		global $wpdb;

		$ip = $this->get_client_ip();
		$wpdb->insert(
			NS_DB::attempts_table(),
			array(
				'ip_address' => $ip,
				'username'   => $this->normalize_username( $username ),
				'success'    => 1,
				'created_at' => current_time( 'mysql', true ),
			),
			array( '%s', '%s', '%d', '%s' )
		);

		foreach ( $this->active_identifiers( $username ) as $identifier ) {
			$wpdb->update(
				NS_DB::lockouts_table(),
				array(
					'fail_count'   => 0,
					'locked_until' => null,
					'updated_at'   => current_time( 'mysql', true ),
				),
				array( 'identifier' => $identifier['value'], 'identifier_type' => $identifier['type'] ),
				array( '%d', '%s', '%s' ),
				array( '%s', '%s' )
			);
		}
	}

	/**
	 * The list of (value, type) identifier pairs currently in play for
	 * this request, based on which of lock_by_ip / lock_by_username are
	 * enabled. A blank username is skipped (nothing meaningful to key on).
	 */
	private function active_identifiers( $username ) {
		$identifiers = array();

		if ( NS_Settings::get( 'lock_by_ip' ) ) {
			$ip = $this->get_client_ip();
			if ( $ip ) {
				$identifiers[] = array( 'value' => $ip, 'type' => 'ip' );
			}
		}

		if ( NS_Settings::get( 'lock_by_username' ) ) {
			$normalized = $this->normalize_username( $username );
			if ( $normalized ) {
				$identifiers[] = array( 'value' => $normalized, 'type' => 'username' );
			}
		}

		return $identifiers;
	}

	private function get_lockout( $identifier, $type ) {
		global $wpdb;
		$table = NS_DB::lockouts_table();
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $table is a fixed internal name, values are prepared below.
		return $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$table} WHERE identifier = %s AND identifier_type = %s",
			$identifier,
			$type
		) );
	}

	private function is_locked( $lockout ) {
		return ! empty( $lockout->locked_until ) && strtotime( $lockout->locked_until ) > time();
	}

	/**
	 * Increments the fail count for one identifier and, once it reaches
	 * the configured threshold, turns it into a lockout — duration grows
	 * exponentially with each repeat offense (e.g. 15, 30, 60, 120 minutes
	 * at the default 2x multiplier), capped at max_lockout_minutes.
	 */
	private function register_failure( $identifier, $type ) {
		global $wpdb;
		$table = NS_DB::lockouts_table();
		$now   = current_time( 'mysql', true );

		$existing = $this->get_lockout( $identifier, $type );

		if ( ! $existing ) {
			$wpdb->insert(
				$table,
				array(
					'identifier'      => $identifier,
					'identifier_type' => $type,
					'fail_count'      => 1,
					'offense_count'   => 0,
					'locked_until'    => null,
					'updated_at'      => $now,
				),
				array( '%s', '%s', '%d', '%d', '%s', '%s' )
			);
			$fail_count    = 1;
			$offense_count = 0;
		} else {
			$fail_count = (int) $existing->fail_count + 1;
			$wpdb->update(
				$table,
				array( 'fail_count' => $fail_count, 'updated_at' => $now ),
				array( 'id' => $existing->id ),
				array( '%d', '%s' ),
				array( '%d' )
			);
			$offense_count = (int) $existing->offense_count;
		}

		$max_attempts = (int) NS_Settings::get( 'max_attempts' );
		if ( $fail_count < $max_attempts ) {
			return;
		}

		$base_minutes = (int) NS_Settings::get( 'lockout_minutes' );
		$multiplier   = (int) NS_Settings::get( 'backoff_multiplier' );
		$cap_minutes  = (int) NS_Settings::get( 'max_lockout_minutes' );

		$duration_minutes = min( $base_minutes * ( $multiplier ** $offense_count ), $cap_minutes );
		$locked_until      = gmdate( 'Y-m-d H:i:s', time() + ( $duration_minutes * MINUTE_IN_SECONDS ) );

		$wpdb->update(
			$table,
			array(
				'fail_count'    => 0,
				'offense_count' => $offense_count + 1,
				'locked_until'  => $locked_until,
				'updated_at'    => $now,
			),
			array( 'identifier' => $identifier, 'identifier_type' => $type ),
			array( '%d', '%d', '%s', '%s' ),
			array( '%s', '%s' )
		);

		/**
		 * Fires when a lockout is newly triggered. Feature 5 (activity
		 * logging + alerts) will hook this to record it and optionally
		 * email the configured alert address — not implemented yet.
		 */
		do_action( 'ns_lockout_triggered', $identifier, $type, $duration_minutes );
	}

	private function normalize_username( $username ) {
		$username = is_string( $username ) ? trim( $username ) : '';
		return $username ? strtolower( sanitize_user( $username, true ) ) : '';
	}

	/**
	 * REMOTE_ADDR only, deliberately — trusting X-Forwarded-For or similar
	 * headers without knowing this specific site sits behind a trusted,
	 * correctly-configured proxy would let an attacker spoof their way
	 * around IP-based lockouts entirely by sending a fake header.
	 */
	private function get_client_ip() {
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}
}
