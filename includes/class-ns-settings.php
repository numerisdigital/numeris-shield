<?php
/**
 * Settings schema, storage, and WordPress Settings API registration.
 *
 * Every configurable value across all five features is declared once in
 * self::schema() — key, type, tab, label, description, default and (where
 * relevant) validation bounds. Registration, sanitization and field
 * rendering are all generated from that single source of truth, so adding
 * a new setting never means touching three different places by hand.
 *
 * Everything lives in one serialized option (self::OPTION_KEY) rather than
 * one option per setting — a single small array is one row in wp_options
 * and one autoload entry, versus dozens of individually-autoloaded rows.
 */

defined( 'ABSPATH' ) || exit;

class NS_Settings {

	const OPTION_KEY = 'numeris_shield_options';
	const GROUP      = 'numeris_shield_group';
	const PAGE       = 'numeris-shield';

	/**
	 * Ordered tab definitions. Order here is the order tabs render in.
	 */
	public static function tabs() {
		return array(
			'general'      => __( 'General', 'numeris-shield' ),
			'login'        => __( 'Login Shield', 'numeris-shield' ),
			'brute_force'  => __( 'Brute-Force Protection', 'numeris-shield' ),
			'twofa'        => __( 'Two-Factor Auth', 'numeris-shield' ),
			'hardening'    => __( 'Core Hardening', 'numeris-shield' ),
			'logging'      => __( 'Activity Logging', 'numeris-shield' ),
		);
	}

	/**
	 * The single source of truth for every setting this plugin has.
	 */
	public static function schema() {
		return array(

			// ---- General ------------------------------------------------
			'keep_data_on_uninstall' => array(
				'tab'         => 'general',
				'type'        => 'bool',
				'label'       => __( 'Keep data on uninstall', 'numeris-shield' ),
				'description' => __( 'When on, deleting this plugin leaves its settings, attempt history and activity log in the database — useful if you\'re reinstalling. Turn off to fully clean up on uninstall.', 'numeris-shield' ),
				'default'     => true,
			),
			'environment_indicator_enabled' => array(
				'tab'         => 'general',
				'type'        => 'bool',
				'label'       => __( 'Show environment indicator', 'numeris-shield' ),
				'description' => __( 'Displays a small Local / Staging / Production badge in the admin bar, so it\'s never ambiguous which environment you\'re currently working in.', 'numeris-shield' ),
				'default'     => true,
			),

			// ---- Login Shield (Feature 1) --------------------------------
			'login_shield_enabled' => array(
				'tab'         => 'login',
				'type'        => 'bool',
				'label'       => __( 'Enable custom login URL', 'numeris-shield' ),
				'description' => __( 'Hides wp-login.php and wp-admin from logged-out visitors (they get a plain 404), and serves your login form at the custom slug below instead.', 'numeris-shield' ),
				'default'     => false,
			),
			'login_slug' => array(
				'tab'         => 'login',
				'type'        => 'slug',
				'label'       => __( 'Custom login slug', 'numeris-shield' ),
				'description' => __( 'e.g. "secure-access" → yoursite.com/secure-access. Cannot match an existing page/post slug or a reserved WordPress path.', 'numeris-shield' ),
				'default'     => '',
			),

			// ---- Brute-Force Protection (Feature 2) ----------------------
			'brute_force_enabled' => array(
				'tab'         => 'brute_force',
				'type'        => 'bool',
				'label'       => __( 'Enable brute-force protection', 'numeris-shield' ),
				'description' => __( 'Locks out an IP address and/or username after too many failed login attempts in a row.', 'numeris-shield' ),
				'default'     => true,
			),
			'lock_by_ip' => array(
				'tab'         => 'brute_force',
				'type'        => 'bool',
				'label'       => __( 'Track by IP address', 'numeris-shield' ),
				'description' => __( 'Locks out the attacker\'s IP address regardless of which username(s) they try.', 'numeris-shield' ),
				'default'     => true,
			),
			'lock_by_username' => array(
				'tab'         => 'brute_force',
				'type'        => 'bool',
				'label'       => __( 'Track by username', 'numeris-shield' ),
				'description' => __( 'Also locks out a specific username if it\'s targeted from many different IPs (distributed attacks).', 'numeris-shield' ),
				'default'     => true,
			),
			'max_attempts' => array(
				'tab'         => 'brute_force',
				'type'        => 'int',
				'min'         => 1,
				'max'         => 50,
				'label'       => __( 'Failed attempts before lockout', 'numeris-shield' ),
				'description' => __( 'Number of consecutive failed logins allowed before locking out.', 'numeris-shield' ),
				'default'     => 5,
			),
			'lockout_minutes' => array(
				'tab'         => 'brute_force',
				'type'        => 'int',
				'min'         => 1,
				'max'         => 10080,
				'label'       => __( 'Base lockout duration (minutes)', 'numeris-shield' ),
				'description' => __( 'How long a first-time lockout lasts.', 'numeris-shield' ),
				'default'     => 15,
			),
			'backoff_multiplier' => array(
				'tab'         => 'brute_force',
				'type'        => 'int',
				'min'         => 1,
				'max'         => 10,
				'label'       => __( 'Repeat-offense backoff multiplier', 'numeris-shield' ),
				'description' => __( 'Each subsequent lockout for the same IP/username is multiplied by this — e.g. 2× turns 15, 30, 60, 120 minutes.', 'numeris-shield' ),
				'default'     => 2,
			),
			'max_lockout_minutes' => array(
				'tab'         => 'brute_force',
				'type'        => 'int',
				'min'         => 1,
				'max'         => 43200,
				'label'       => __( 'Maximum lockout duration (minutes)', 'numeris-shield' ),
				'description' => __( 'Caps how long the exponential backoff can grow to. Default is 24 hours.', 'numeris-shield' ),
				'default'     => 1440,
			),

			// ---- Two-Factor Auth (Feature 3) -----------------------------
			'twofa_enabled' => array(
				'tab'         => 'twofa',
				'type'        => 'bool',
				'label'       => __( 'Enable two-factor authentication', 'numeris-shield' ),
				'description' => __( 'Lets users secure their account with a TOTP authenticator app (Google Authenticator, Authy, 1Password, etc).', 'numeris-shield' ),
				'default'     => true,
			),
			'twofa_enforced_roles' => array(
				'tab'         => 'twofa',
				'type'        => 'roles',
				'label'       => __( 'Require 2FA for these roles', 'numeris-shield' ),
				'description' => __( 'Users in these roles must set up 2FA to keep using the site (after the grace period below).', 'numeris-shield' ),
				'default'     => array( 'administrator' ),
			),
			'twofa_grace_period_days' => array(
				'tab'         => 'twofa',
				'type'        => 'int',
				'min'         => 0,
				'max'         => 30,
				'label'       => __( 'Grace period (days)', 'numeris-shield' ),
				'description' => __( 'How long an enforced user has to set up 2FA before they\'re required to on every login. 0 means immediately.', 'numeris-shield' ),
				'default'     => 3,
			),
			'backup_codes_count' => array(
				'tab'         => 'twofa',
				'type'        => 'int',
				'min'         => 4,
				'max'         => 20,
				'label'       => __( 'Backup codes to generate', 'numeris-shield' ),
				'description' => __( 'Single-use recovery codes generated when a user enables 2FA.', 'numeris-shield' ),
				'default'     => 10,
			),

			// ---- Core Hardening (Feature 4) ------------------------------
			'disable_xmlrpc' => array(
				'tab'         => 'hardening',
				'type'        => 'bool',
				'label'       => __( 'Disable XML-RPC', 'numeris-shield' ),
				'description' => __( 'XML-RPC is rarely needed today and is a common brute-force/amplification target.', 'numeris-shield' ),
				'default'     => true,
			),
			'block_user_enumeration' => array(
				'tab'         => 'hardening',
				'type'        => 'bool',
				'label'       => __( 'Block user enumeration', 'numeris-shield' ),
				'description' => __( 'Prevents discovering valid usernames via ?author=N URLs and the REST API users endpoint.', 'numeris-shield' ),
				'default'     => true,
			),
			'hide_wp_version' => array(
				'tab'         => 'hardening',
				'type'        => 'bool',
				'label'       => __( 'Hide WordPress version', 'numeris-shield' ),
				'description' => __( 'Removes the version number from page source, RSS feeds and response headers, so attackers can\'t target known vulnerabilities by version.', 'numeris-shield' ),
				'default'     => true,
			),
			'disable_file_editor' => array(
				'tab'         => 'hardening',
				'type'        => 'bool',
				'label'       => __( 'Disable theme/plugin file editor', 'numeris-shield' ),
				'description' => __( 'Turns off the built-in Appearance/Plugins code editors — the single most common way a compromised admin account is used to plant malware.', 'numeris-shield' ),
				'default'     => true,
			),
			'security_headers_enabled' => array(
				'tab'         => 'hardening',
				'type'        => 'bool',
				'label'       => __( 'Send security headers', 'numeris-shield' ),
				'description' => __( 'Adds X-Frame-Options, X-Content-Type-Options and Referrer-Policy headers to every response.', 'numeris-shield' ),
				'default'     => true,
			),

			// ---- Activity Logging (Feature 5) ----------------------------
			'log_retention_days' => array(
				'tab'         => 'logging',
				'type'        => 'int',
				'min'         => 1,
				'max'         => 3650,
				'label'       => __( 'Keep log entries for (days)', 'numeris-shield' ),
				'description' => __( 'Older entries are pruned automatically on a daily schedule.', 'numeris-shield' ),
				'default'     => 90,
			),
			'alert_email' => array(
				'tab'         => 'logging',
				'type'        => 'email',
				'label'       => __( 'Alert email address', 'numeris-shield' ),
				'description' => __( 'Where security alerts below are sent. Defaults to the site admin email.', 'numeris-shield' ),
				'default'     => '', // Resolved to get_option('admin_email') at read time if left blank.
			),
			'alert_on_lockout' => array(
				'tab'         => 'logging',
				'type'        => 'bool',
				'label'       => __( 'Alert when a lockout is triggered', 'numeris-shield' ),
				'default'     => true,
			),
			'alert_on_new_admin' => array(
				'tab'         => 'logging',
				'type'        => 'bool',
				'label'       => __( 'Alert when a new administrator is created', 'numeris-shield' ),
				'default'     => true,
			),
			'alert_on_2fa_disabled' => array(
				'tab'         => 'logging',
				'type'        => 'bool',
				'label'       => __( 'Alert when a user disables 2FA', 'numeris-shield' ),
				'default'     => true,
			),
		);
	}

	public static function defaults() {
		$defaults = array();
		foreach ( self::schema() as $key => $field ) {
			$defaults[ $key ] = $field['default'];
		}
		return $defaults;
	}

	/**
	 * Adds the option (with full defaults) only if it doesn't exist yet —
	 * safe to call on every activation without clobbering existing settings.
	 */
	public static function maybe_set_defaults() {
		if ( false === get_option( self::OPTION_KEY, false ) ) {
			add_option( self::OPTION_KEY, self::defaults() );
		}
	}

	private static $cache = null;

	public static function get_all() {
		if ( null === self::$cache ) {
			self::$cache = wp_parse_args( get_option( self::OPTION_KEY, array() ), self::defaults() );
		}
		return self::$cache;
	}

	public static function get( $key, $default = null ) {
		$all = self::get_all();
		if ( array_key_exists( $key, $all ) ) {
			return $all[ $key ];
		}
		$schema = self::schema();
		return $default ?? ( $schema[ $key ]['default'] ?? null );
	}

	/**
	 * The alert email resolves to the site admin email when left blank,
	 * rather than storing that as a "default" that could go stale.
	 */
	public static function alert_email() {
		$configured = self::get( 'alert_email' );
		return $configured ? $configured : get_option( 'admin_email' );
	}

	/* ── Settings API registration ─────────────────────────────────── */

	public static function register() {
		register_setting( self::GROUP, self::OPTION_KEY, array(
			'type'              => 'array',
			'sanitize_callback' => array( __CLASS__, 'sanitize' ),
			'default'           => self::defaults(),
		) );

		foreach ( self::tabs() as $tab_id => $tab_label ) {
			add_settings_section(
				"ns_section_{$tab_id}",
				$tab_label,
				'__return_false', // Section intro text is rendered by the admin page template instead, per-tab.
				self::PAGE
			);
		}

		foreach ( self::schema() as $key => $field ) {
			add_settings_field(
				"ns_field_{$key}",
				$field['label'],
				array( __CLASS__, 'render_field' ),
				self::PAGE,
				"ns_section_{$field['tab']}",
				array( 'key' => $key, 'field' => $field )
			);
		}
	}

	/**
	 * Renders a single field's input based on its schema type. All values
	 * are read fresh from the posted/stored option, never hardcoded.
	 */
	public static function render_field( $args ) {
		$key   = $args['key'];
		$field = $args['field'];
		$value = self::get( $key );
		$name  = self::OPTION_KEY . "[{$key}]";
		$id    = "ns_field_{$key}";

		switch ( $field['type'] ) {

			case 'bool':
				printf(
					'<label class="ns-toggle" for="%1$s"><input type="checkbox" id="%1$s" name="%2$s" value="1" %3$s><span class="ns-track"><span class="ns-thumb"></span></span></label>',
					esc_attr( $id ),
					esc_attr( $name ),
					checked( (bool) $value, true, false )
				);
				break;

			case 'int':
				printf(
					'<input type="number" id="%1$s" name="%2$s" value="%3$s" min="%4$s" max="%5$s" class="small-text">',
					esc_attr( $id ),
					esc_attr( $name ),
					esc_attr( (int) $value ),
					esc_attr( $field['min'] ?? 0 ),
					esc_attr( $field['max'] ?? 999999 )
				);
				break;

			case 'email':
				printf(
					'<input type="email" id="%1$s" name="%2$s" value="%3$s" class="regular-text" placeholder="%4$s">',
					esc_attr( $id ),
					esc_attr( $name ),
					esc_attr( $value ),
					esc_attr( get_option( 'admin_email' ) )
				);
				break;

			case 'slug':
				printf(
					'<code>%1$s/</code> <input type="text" id="%2$s" name="%3$s" value="%4$s" class="regular-text" placeholder="secure-access">',
					esc_html( home_url( '' ) ),
					esc_attr( $id ),
					esc_attr( $name ),
					esc_attr( $value )
				);
				break;

			case 'roles':
				$all_roles = function_exists( 'wp_roles' ) ? wp_roles()->get_names() : array();
				$selected  = (array) $value;
				foreach ( $all_roles as $role_key => $role_label ) {
					printf(
						'<label style="display:block;margin-bottom:4px;"><input type="checkbox" name="%1$s[]" value="%2$s" %3$s> %4$s</label>',
						esc_attr( $name ),
						esc_attr( $role_key ),
						checked( in_array( $role_key, $selected, true ), true, false ),
						esc_html( translate_user_role( $role_label ) )
					);
				}
				break;
		}

		if ( ! empty( $field['description'] ) ) {
			printf( '<p class="description">%s</p>', wp_kses_post( $field['description'] ) );
		}
	}

	/**
	 * Sanitizes the whole posted options array against the schema. Runs
	 * regardless of which tab was visually active when Save was clicked —
	 * the admin page renders every tab's fields in the same <form> (hidden
	 * via CSS, not removed from the DOM) specifically so this never has to
	 * guess which fields were "supposed" to be present.
	 */
	public static function sanitize( $input ) {
		$input   = is_array( $input ) ? $input : array();
		$current = self::get_all();
		$output  = array();

		foreach ( self::schema() as $key => $field ) {
			switch ( $field['type'] ) {

				case 'bool':
					$output[ $key ] = ! empty( $input[ $key ] );
					break;

				case 'int':
					$val = isset( $input[ $key ] ) ? (int) $input[ $key ] : (int) $field['default'];
					$min = $field['min'] ?? 0;
					$max = $field['max'] ?? 999999;
					$output[ $key ] = max( $min, min( $max, $val ) );
					break;

				case 'email':
					$val = isset( $input[ $key ] ) ? sanitize_email( wp_unslash( $input[ $key ] ) ) : '';
					$output[ $key ] = ( '' === $val || is_email( $val ) ) ? $val : $current[ $key ];
					break;

				case 'roles':
					$posted    = isset( $input[ $key ] ) ? (array) $input[ $key ] : array();
					$all_roles = function_exists( 'wp_roles' ) ? array_keys( wp_roles()->get_names() ) : array();
					$output[ $key ] = array_values( array_intersect( $posted, $all_roles ) );
					break;

				case 'slug':
					$output[ $key ] = self::sanitize_login_slug( $input[ $key ] ?? '', $current[ $key ] );
					break;

				default:
					$output[ $key ] = isset( $input[ $key ] ) ? sanitize_text_field( wp_unslash( $input[ $key ] ) ) : $current[ $key ];
			}
		}

		// Safety net: never allow the login shield to be "on" with an empty
		// slug — that combination would 404 wp-login.php/wp-admin with
		// nowhere else to log in from.
		if ( $output['login_shield_enabled'] && '' === $output['login_slug'] ) {
			$output['login_shield_enabled'] = false;
			add_settings_error(
				self::OPTION_KEY,
				'ns_login_slug_required',
				__( 'Custom login URL was not enabled because no slug was set.', 'numeris-shield' )
			);
		}

		return $output;
	}

	/**
	 * Validates a candidate login slug: must be a clean slug, and must not
	 * collide with a reserved WordPress path or an existing page/post —
	 * either of which would make routing ambiguous or break the shield.
	 * On any validation failure, keeps the previously-saved value rather
	 * than saving something broken.
	 */
	private static function sanitize_login_slug( $raw, $previous ) {
		$raw = wp_unslash( $raw );
		if ( '' === trim( $raw ) ) {
			return '';
		}

		$slug = sanitize_title( $raw );

		$reserved = array( 'wp-admin', 'wp-login', 'wp-login.php', 'wp-content', 'wp-includes', 'wp-json', 'xmlrpc.php', 'admin-ajax', 'admin-ajax.php', 'admin-post', 'admin-post.php', 'feed' );
		if ( '' === $slug || in_array( $slug, $reserved, true ) ) {
			add_settings_error(
				self::OPTION_KEY,
				'ns_login_slug_reserved',
				__( 'That login slug is reserved by WordPress and can\'t be used. Your previous slug was kept.', 'numeris-shield' )
			);
			return $previous;
		}

		if ( $slug !== $previous ) {
			$existing = get_page_by_path( $slug, OBJECT, array( 'page', 'post' ) );
			if ( $existing ) {
				add_settings_error(
					self::OPTION_KEY,
					'ns_login_slug_collision',
					sprintf(
						/* translators: %s: the conflicting slug */
						__( 'The slug "%s" is already used by an existing page or post. Your previous slug was kept.', 'numeris-shield' ),
						$slug
					)
				);
				return $previous;
			}
		}

		return $slug;
	}
}
