<?php
/**
 * Settings screen: one <form> posting to options.php (genuine Settings
 * API), with every tab's fields always present in the page — just shown
 * or hidden by CSS/JS depending on which tab is active. This is what makes
 * "tabs" and "a single Settings API form" compatible: if only the active
 * tab's fields were rendered, saving would wipe every other tab's values
 * (they'd simply be absent from $_POST), since Settings API rebuilds the
 * whole option from whatever was submitted.
 */

defined( 'ABSPATH' ) || exit;

class NS_Admin_Page {

	const MENU_SLUG = 'numeris-shield';

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
	}

	public function add_menu() {
		add_menu_page(
			__( 'Numeris Shield', 'numeris-shield' ),
			__( 'Numeris Shield', 'numeris-shield' ),
			'manage_options',
			self::MENU_SLUG,
			array( $this, 'render_page' ),
			'dashicons-shield',
			80
		);

		// Without this, the auto-created first submenu item just repeats
		// the top-level label ("Numeris Shield" twice) — explicitly
		// re-adding it with the same slug renames that entry instead of
		// creating a duplicate.
		add_submenu_page(
			self::MENU_SLUG,
			__( 'Settings', 'numeris-shield' ),
			__( 'Settings', 'numeris-shield' ),
			'manage_options',
			self::MENU_SLUG,
			array( $this, 'render_page' )
		);
	}

	public function enqueue_assets( $hook ) {
		if ( ! in_array( $hook, array( 'toplevel_page_' . self::MENU_SLUG, 'numeris-shield_page_' . NS_Log_Page::MENU_SLUG ), true ) ) {
			return;
		}
		wp_enqueue_style( 'ns-admin', NS_URL . 'admin/assets/admin.css', array(), NS_VERSION );
		wp_enqueue_script( 'ns-admin', NS_URL . 'admin/assets/admin.js', array(), NS_VERSION, true );
	}

	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$tabs        = NS_Settings::tabs();
		$active_tab  = isset( $_GET['tab'] ) && array_key_exists( $_GET['tab'], $tabs ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : array_key_first( $tabs );

		$tab_intros = array(
			'general'     => __( 'Plugin-wide behaviour that doesn\'t belong to any one feature.', 'numeris-shield' ),
			'login'       => __( 'Move the login form off the well-known wp-login.php / wp-admin URLs.', 'numeris-shield' ),
			'brute_force' => __( 'Not yet enforced — settings are ready, the lockout logic is next.', 'numeris-shield' ),
			'twofa'       => __( 'Not yet enforced — settings are ready, TOTP enrolment is next.', 'numeris-shield' ),
			'hardening'   => __( 'Not yet enforced — settings are ready, the hardening measures are next.', 'numeris-shield' ),
			'logging'     => __( 'Not yet recording — settings are ready, the activity log is next.', 'numeris-shield' ),
		);
		?>
		<div class="wrap ns-wrap">
			<div class="ns-header">
				<span class="dashicons dashicons-shield ns-header-icon"></span>
				<h1><?php esc_html_e( 'Numeris Shield', 'numeris-shield' ); ?></h1>
			</div>

			<?php settings_errors(); ?>

			<nav class="ns-tabs" aria-label="<?php esc_attr_e( 'Settings tabs', 'numeris-shield' ); ?>">
				<?php foreach ( $tabs as $tab_id => $tab_label ) : ?>
					<a href="<?php echo esc_url( add_query_arg( array( 'page' => self::MENU_SLUG, 'tab' => $tab_id ), admin_url( 'admin.php' ) ) ); ?>"
					   class="ns-tab<?php echo $tab_id === $active_tab ? ' is-active' : ''; ?>"
					   data-tab="<?php echo esc_attr( $tab_id ); ?>">
						<?php echo esc_html( $tab_label ); ?>
					</a>
				<?php endforeach; ?>
			</nav>

			<form method="post" action="options.php">
				<?php settings_fields( NS_Settings::GROUP ); ?>

				<?php foreach ( $tabs as $tab_id => $tab_label ) : ?>
					<div class="ns-tab-panel" data-tab="<?php echo esc_attr( $tab_id ); ?>" <?php echo $tab_id === $active_tab ? '' : 'hidden'; ?>>
						<div class="ns-card">
							<?php if ( ! empty( $tab_intros[ $tab_id ] ) ) : ?>
								<p class="ns-intro"><?php echo esc_html( $tab_intros[ $tab_id ] ); ?></p>
							<?php endif; ?>
							<table class="form-table" role="presentation">
								<?php do_settings_fields( NS_Settings::PAGE, "ns_section_{$tab_id}" ); ?>
							</table>
						</div>
					</div>
				<?php endforeach; ?>

				<?php submit_button( __( 'Save Settings', 'numeris-shield' ) ); ?>
			</form>
		</div>
		<?php
	}
}
