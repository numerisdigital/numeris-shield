<?php
/**
 * Feature 3: Two-Factor Authentication.
 *
 * Profile UI is AJAX-driven rather than a server-rendered <form>, because
 * show_user_profile/edit_user_profile fire *inside* WordPress's own
 * profile.php <form id="your-profile">...</form> — nesting another <form>
 * in there is invalid HTML and browsers handle it inconsistently, so the
 * setup/disable/regenerate actions all go through admin-ajax.php instead.
 *
 * The login-time code challenge is a separate interstitial screen, not an
 * inline error on the normal login form: after a correct password, we
 * deliberately do NOT complete the login. A short-lived token identifying
 * the user is stashed server-side and the browser is redirected to a
 * dedicated "enter your code" screen; only a correct TOTP or backup code
 * against *that* token actually calls wp_set_auth_cookie(). This keeps the
 * password and the second factor as two genuinely separate checks rather
 * than trusting anything client-side.
 */

defined( 'ABSPATH' ) || exit;

class NS_Two_Factor {

	const NONCE_ACTION = 'ns_2fa_nonce';
	const MAX_CHALLENGE_ATTEMPTS = 5;

	public function __construct() {
		if ( NUMERIS_SHIELD_DISABLE ) {
			return;
		}
		if ( ! NS_Settings::get( 'twofa_enabled' ) ) {
			return;
		}

		add_action( 'show_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_profile_assets' ) );

		// Self-service only — deliberately no _nopriv_ variants, and every
		// handler below re-checks that the target user_id is the logged-in
		// user, so viewing someone else's profile as an admin never allows
		// silently enabling/disabling *their* 2FA.
		add_action( 'wp_ajax_ns_2fa_start_setup', array( $this, 'ajax_start_setup' ) );
		add_action( 'wp_ajax_ns_2fa_confirm_setup', array( $this, 'ajax_confirm_setup' ) );
		add_action( 'wp_ajax_ns_2fa_disable', array( $this, 'ajax_disable' ) );
		add_action( 'wp_ajax_ns_2fa_regenerate_backup_codes', array( $this, 'ajax_regenerate_backup_codes' ) );

		// Priority 50: after NS_Brute_Force's own checks (30, 40) on the
		// same filter, so a locked-out identifier never even reaches the
		// 2FA challenge.
		add_filter( 'authenticate', array( $this, 'maybe_require_challenge' ), 50, 1 );
		add_action( 'login_init', array( $this, 'maybe_render_challenge' ) );

		add_action( 'admin_init', array( $this, 'enforce_setup_if_required' ) );
		add_action( 'admin_notices', array( $this, 'grace_period_notice' ) );
	}

	/* ── Profile UI ───────────────────────────────────────────────────── */

	public function enqueue_profile_assets( $hook ) {
		if ( ! in_array( $hook, array( 'profile.php', 'user-edit.php' ), true ) ) {
			return;
		}
		wp_enqueue_style( 'ns-admin', NS_URL . 'admin/assets/admin.css', array(), NS_VERSION );
		wp_enqueue_script( 'ns-two-factor', NS_URL . 'admin/assets/two-factor.js', array(), NS_VERSION, true );
		wp_localize_script( 'ns-two-factor', 'nsTwoFactor', array(
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( self::NONCE_ACTION ),
			'i18n'    => array(
				'enterPassword'  => __( 'Enter your account password to confirm:', 'numeris-shield' ),
				'confirmRegen'   => __( 'Regenerate backup codes? Your existing codes will stop working.', 'numeris-shield' ),
				'genericError'   => __( 'Something went wrong. Please try again.', 'numeris-shield' ),
			),
		) );
	}

	public function render_profile_section( $user ) {
		$is_self   = get_current_user_id() === $user->ID;
		$enabled   = $this->is_enabled( $user->ID );
		$remaining = $enabled ? $this->count_unused_backup_codes( $user->ID ) : 0;
		?>
		<h2 id="ns-2fa-setup"><?php esc_html_e( 'Two-Factor Authentication', 'numeris-shield' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Status', 'numeris-shield' ); ?></th>
				<td>
					<?php if ( $enabled ) : ?>
						<p><strong style="color:#1a7f37;">&#10003; <?php esc_html_e( 'Enabled', 'numeris-shield' ); ?></strong></p>
						<p class="description">
							<?php
							printf(
								/* translators: %d: number of unused backup codes */
								esc_html( _n( '%d backup code remaining.', '%d backup codes remaining.', $remaining, 'numeris-shield' ) ),
								(int) $remaining
							);
							?>
						</p>
					<?php else : ?>
						<p><strong style="color:#8a8a8a;"><?php esc_html_e( 'Not enabled', 'numeris-shield' ); ?></strong></p>
					<?php endif; ?>

					<?php if ( ! $is_self ) : ?>
						<p class="description"><?php esc_html_e( 'Users can only manage their own two-factor authentication.', 'numeris-shield' ); ?></p>
					<?php else : ?>
						<div id="ns-2fa-app" data-user-id="<?php echo esc_attr( $user->ID ); ?>">
							<?php if ( $enabled ) : ?>
								<button type="button" class="button" id="ns-2fa-regenerate-codes"><?php esc_html_e( 'Regenerate backup codes', 'numeris-shield' ); ?></button>
								<button type="button" class="button" id="ns-2fa-disable"><?php esc_html_e( 'Disable 2FA', 'numeris-shield' ); ?></button>
							<?php else : ?>
								<button type="button" class="button button-primary" id="ns-2fa-start"><?php esc_html_e( 'Enable Two-Factor Authentication', 'numeris-shield' ); ?></button>
							<?php endif; ?>
							<div id="ns-2fa-panel"></div>
						</div>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
	}

	/* ── AJAX handlers ────────────────────────────────────────────────── */

	private function check_ajax_self() {
		check_ajax_referer( self::NONCE_ACTION, 'nonce' );
		$user_id = absint( $_POST['user_id'] ?? 0 );
		if ( ! is_user_logged_in() || get_current_user_id() !== $user_id ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'numeris-shield' ) ) );
		}
		return $user_id;
	}

	public function ajax_start_setup() {
		$user_id = $this->check_ajax_self();

		$secret = NS_TOTP::generate_secret();
		set_transient( 'ns_2fa_pending_' . $user_id, $secret, 15 * MINUTE_IN_SECONDS );

		$user       = get_userdata( $user_id );
		$issuer     = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$qr_uri     = NS_TOTP::get_otpauth_uri_minimal( $secret, $user->user_login, $issuer );
		$full_uri   = NS_TOTP::get_otpauth_uri( $secret, $user->user_login, $issuer );
		$qr_result  = NS_QR_Encoder::encode( $qr_uri );

		wp_send_json_success( array(
			'qr_svg'      => $qr_result['ok'] ? NS_QR_Encoder::to_svg( $qr_result, 6 ) : '',
			'manual_key'  => NS_TOTP::format_secret_for_display( $secret ),
			'otpauth_uri' => $full_uri,
		) );
	}

	public function ajax_confirm_setup() {
		$user_id = $this->check_ajax_self();

		$code   = sanitize_text_field( wp_unslash( $_POST['code'] ?? '' ) );
		$secret = get_transient( 'ns_2fa_pending_' . $user_id );
		if ( ! $secret ) {
			wp_send_json_error( array( 'message' => __( 'Setup session expired — please start again.', 'numeris-shield' ) ) );
		}
		if ( ! NS_TOTP::verify_code( $secret, $code ) ) {
			wp_send_json_error( array( 'message' => __( "That code didn't match. Please try again.", 'numeris-shield' ) ) );
		}

		update_user_meta( $user_id, '_ns_2fa_secret', $secret );
		update_user_meta( $user_id, '_ns_2fa_enabled', '1' );
		delete_user_meta( $user_id, '_ns_2fa_grace_start' );
		delete_transient( 'ns_2fa_pending_' . $user_id );

		$codes = $this->generate_and_store_backup_codes( $user_id );

		/** Feature 5 will hook this to log it and optionally alert. */
		do_action( 'ns_2fa_enabled', $user_id );

		wp_send_json_success( array( 'backup_codes' => $codes ) );
	}

	public function ajax_disable() {
		$user_id = $this->check_ajax_self();

		$password = (string) ( $_POST['password'] ?? '' );
		$user     = get_userdata( $user_id );
		if ( ! $user || ! wp_check_password( $password, $user->user_pass, $user_id ) ) {
			wp_send_json_error( array( 'message' => __( 'Incorrect password.', 'numeris-shield' ) ) );
		}

		delete_user_meta( $user_id, '_ns_2fa_secret' );
		delete_user_meta( $user_id, '_ns_2fa_enabled' );
		delete_user_meta( $user_id, '_ns_2fa_backup_codes' );
		delete_user_meta( $user_id, '_ns_2fa_grace_start' );

		/** Feature 5 will hook this — disabling 2FA is alert-worthy by default (see NS_Settings). */
		do_action( 'ns_2fa_disabled', $user_id );

		wp_send_json_success();
	}

	public function ajax_regenerate_backup_codes() {
		$user_id = $this->check_ajax_self();

		if ( ! $this->is_enabled( $user_id ) ) {
			wp_send_json_error( array( 'message' => __( '2FA is not enabled.', 'numeris-shield' ) ) );
		}

		$codes = $this->generate_and_store_backup_codes( $user_id );
		wp_send_json_success( array( 'backup_codes' => $codes ) );
	}

	private function generate_and_store_backup_codes( $user_id ) {
		$count  = (int) NS_Settings::get( 'backup_codes_count' );
		$codes  = NS_TOTP::generate_backup_codes( $count );
		$stored = array();
		foreach ( $codes as $code ) {
			$stored[] = array( 'hash' => NS_TOTP::hash_backup_code( $code ), 'used' => false );
		}
		update_user_meta( $user_id, '_ns_2fa_backup_codes', $stored );
		return $codes;
	}

	/* ── Login-time challenge ─────────────────────────────────────────── */

	/**
	 * If primary auth just succeeded and this user has 2FA enabled, don't
	 * let wp_authenticate() return a WP_User at all — stash a short-lived
	 * token and redirect to the code-entry screen instead. The login is
	 * only actually completed (wp_set_auth_cookie) once that token's code
	 * checks out, in handle_challenge_submission() below.
	 */
	public function maybe_require_challenge( $user ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return $user;
		}
		if ( ! $this->is_enabled( $user->ID ) ) {
			return $user;
		}

		$token       = wp_generate_password( 32, false );
		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : admin_url();
		set_transient( 'ns_2fa_login_' . $token, array(
			'user_id'     => $user->ID,
			'redirect_to' => $redirect_to,
			'attempts'    => 0,
		), 10 * MINUTE_IN_SECONDS );

		wp_safe_redirect( add_query_arg( 'ns_2fa_token', $token, wp_login_url() ) );
		exit;
	}

	/**
	 * Hooked on login_init, which fires unconditionally at the top of
	 * wp-login.php's own execution — whether that's the real file or
	 * NS_Login_Shield serving it in place at the custom slug — so this
	 * works regardless of whether Feature 1 is enabled.
	 */
	public function maybe_render_challenge() {
		if ( ! isset( $_GET['ns_2fa_token'] ) && ! isset( $_POST['ns_2fa_token'] ) ) {
			return;
		}

		$token = sanitize_text_field( wp_unslash( $_REQUEST['ns_2fa_token'] ) );
		$data  = get_transient( 'ns_2fa_login_' . $token );

		if ( ! $data ) {
			$this->render_challenge_expired();
			exit;
		}

		if ( 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
			$this->handle_challenge_submission( $token, $data );
			exit;
		}

		$this->render_challenge_form( $token, '' );
		exit;
	}

	private function handle_challenge_submission( $token, $data ) {
		$code    = sanitize_text_field( wp_unslash( $_POST['ns_2fa_code'] ?? '' ) );
		$user_id = (int) $data['user_id'];
		$secret  = get_user_meta( $user_id, '_ns_2fa_secret', true );

		$valid = $secret && NS_TOTP::verify_code( $secret, $code );
		if ( ! $valid ) {
			$valid = $this->try_backup_code( $user_id, $code );
		}

		if ( ! $valid ) {
			$data['attempts'] = (int) $data['attempts'] + 1;
			if ( $data['attempts'] >= self::MAX_CHALLENGE_ATTEMPTS ) {
				delete_transient( 'ns_2fa_login_' . $token );
				$this->render_challenge_expired( __( 'Too many incorrect attempts — please log in again.', 'numeris-shield' ) );
				return;
			}
			set_transient( 'ns_2fa_login_' . $token, $data, 10 * MINUTE_IN_SECONDS );
			$this->render_challenge_form( $token, __( 'Incorrect code. Please try again.', 'numeris-shield' ) );
			return;
		}

		delete_transient( 'ns_2fa_login_' . $token );

		$user = get_userdata( $user_id );
		wp_set_auth_cookie( $user_id, ! empty( $_POST['rememberme'] ) );
		wp_set_current_user( $user_id );
		do_action( 'wp_login', $user->user_login, $user );

		wp_safe_redirect( $data['redirect_to'] );
	}

	private function try_backup_code( $user_id, $code ) {
		$codes = get_user_meta( $user_id, '_ns_2fa_backup_codes', true );
		if ( ! is_array( $codes ) ) {
			return false;
		}

		foreach ( $codes as $i => $entry ) {
			if ( ! empty( $entry['used'] ) ) {
				continue;
			}
			if ( NS_TOTP::verify_backup_code( $code, $entry['hash'] ) ) {
				$codes[ $i ]['used']    = true;
				$codes[ $i ]['used_at'] = current_time( 'mysql', true );
				update_user_meta( $user_id, '_ns_2fa_backup_codes', $codes );
				return true;
			}
		}
		return false;
	}

	private function render_challenge_form( $token, $error ) {
		login_header(
			__( 'Two-Factor Authentication', 'numeris-shield' ),
			'',
			$error ? new WP_Error( 'ns_2fa_error', $error ) : null
		);
		?>
		<form name="ns_2fa_form" id="ns_2fa_form" method="post" action="<?php echo esc_url( add_query_arg( 'ns_2fa_token', $token, wp_login_url() ) ); ?>">
			<p>
				<label for="ns_2fa_code"><?php esc_html_e( 'Authentication code', 'numeris-shield' ); ?></label>
				<input type="text" name="ns_2fa_code" id="ns_2fa_code" class="input" value="" size="20" autocomplete="one-time-code" autofocus>
			</p>
			<p class="description"><?php esc_html_e( 'Enter the 6-digit code from your authenticator app, or one of your backup codes.', 'numeris-shield' ); ?></p>
			<input type="hidden" name="ns_2fa_token" value="<?php echo esc_attr( $token ); ?>">
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'numeris-shield' ); ?>">
			</p>
		</form>
		<p id="backtoblog"><a href="<?php echo esc_url( wp_login_url() ); ?>">&larr; <?php esc_html_e( 'Back to login', 'numeris-shield' ); ?></a></p>
		<?php
		login_footer();
	}

	private function render_challenge_expired( $message = '' ) {
		login_header(
			__( 'Session Expired', 'numeris-shield' ),
			'',
			new WP_Error( 'ns_2fa_expired', $message ?: __( 'This verification step has expired. Please log in again.', 'numeris-shield' ) )
		);
		?>
		<p id="backtoblog"><a href="<?php echo esc_url( wp_login_url() ); ?>">&larr; <?php esc_html_e( 'Back to login', 'numeris-shield' ); ?></a></p>
		<?php
		login_footer();
	}

	/* ── Enforcement / grace period ───────────────────────────────────── */

	public function enforce_setup_if_required() {
		if ( wp_doing_ajax() ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! $user || ! $user->exists() ) {
			return;
		}
		if ( $this->is_enabled( $user->ID ) || ! $this->is_role_enforced( $user ) ) {
			return;
		}

		global $pagenow;
		if ( in_array( $pagenow, array( 'profile.php', 'admin-ajax.php', 'admin-post.php' ), true ) ) {
			return;
		}

		$grace_start = get_user_meta( $user->ID, '_ns_2fa_grace_start', true );
		if ( ! $grace_start ) {
			// First time we've seen this enforced-but-unconfigured user —
			// start their clock rather than blocking this very page load.
			update_user_meta( $user->ID, '_ns_2fa_grace_start', time() );
			return;
		}

		$grace_days = (int) NS_Settings::get( 'twofa_grace_period_days' );
		$deadline   = (int) $grace_start + ( $grace_days * DAY_IN_SECONDS );
		if ( time() < $deadline ) {
			return;
		}

		wp_safe_redirect( admin_url( 'profile.php#ns-2fa-setup' ) );
		exit;
	}

	public function grace_period_notice() {
		$user = wp_get_current_user();
		if ( ! $user || ! $user->exists() ) {
			return;
		}
		if ( $this->is_enabled( $user->ID ) || ! $this->is_role_enforced( $user ) ) {
			return;
		}

		$grace_start = get_user_meta( $user->ID, '_ns_2fa_grace_start', true );
		if ( ! $grace_start ) {
			return;
		}

		$grace_days = (int) NS_Settings::get( 'twofa_grace_period_days' );
		$deadline   = (int) $grace_start + ( $grace_days * DAY_IN_SECONDS );
		if ( time() >= $deadline ) {
			return; // enforce_setup_if_required() already hard-blocks by this point.
		}

		$days_left = max( 0, (int) ceil( ( $deadline - time() ) / DAY_IN_SECONDS ) );
		printf(
			'<div class="notice notice-warning"><p>%s</p></div>',
			esc_html(
				sprintf(
					/* translators: %d: days remaining */
					_n(
						'Your account requires two-factor authentication. You have %d day left to set it up on your profile page.',
						'Your account requires two-factor authentication. You have %d days left to set it up on your profile page.',
						$days_left,
						'numeris-shield'
					),
					$days_left
				)
			)
		);
	}

	/* ── Helpers ──────────────────────────────────────────────────────── */

	private function is_enabled( $user_id ) {
		return (bool) get_user_meta( $user_id, '_ns_2fa_enabled', true ) && get_user_meta( $user_id, '_ns_2fa_secret', true );
	}

	private function is_role_enforced( $user ) {
		$enforced_roles = (array) NS_Settings::get( 'twofa_enforced_roles' );
		if ( empty( $enforced_roles ) ) {
			return false;
		}
		return (bool) array_intersect( $enforced_roles, (array) $user->roles );
	}

	private function count_unused_backup_codes( $user_id ) {
		$codes = get_user_meta( $user_id, '_ns_2fa_backup_codes', true );
		if ( ! is_array( $codes ) ) {
			return 0;
		}
		return count( array_filter( $codes, function ( $c ) {
			return empty( $c['used'] );
		} ) );
	}
}
