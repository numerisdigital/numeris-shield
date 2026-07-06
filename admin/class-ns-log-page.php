<?php
/**
 * The "Activity Log" submenu page — read-only viewer over the ns_activity_log
 * table, with severity filtering and a manual "clear all" utility.
 */

defined( 'ABSPATH' ) || exit;

class NS_Log_Page {

	const MENU_SLUG = 'numeris-shield-log';

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'add_menu' ), 20 );
		add_action( 'admin_post_ns_clear_logs', array( $this, 'handle_clear_logs' ) );
	}

	public function add_menu() {
		add_submenu_page(
			NS_Admin_Page::MENU_SLUG,
			__( 'Activity Log', 'numeris-shield' ),
			__( 'Activity Log', 'numeris-shield' ),
			'manage_options',
			self::MENU_SLUG,
			array( $this, 'render_page' )
		);
	}

	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		require_once NS_DIR . 'admin/class-ns-log-list-table.php';
		$table = new NS_Log_List_Table();
		$table->prepare_items();
		?>
		<div class="wrap ns-wrap">
			<div class="ns-header">
				<span class="dashicons dashicons-shield ns-header-icon"></span>
				<h1><?php esc_html_e( 'Activity Log', 'numeris-shield' ); ?></h1>
			</div>

			<?php if ( isset( $_GET['cleared'] ) ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Activity log cleared.', 'numeris-shield' ); ?></p></div>
			<?php endif; ?>

			<form method="get">
				<input type="hidden" name="page" value="<?php echo esc_attr( self::MENU_SLUG ); ?>">
				<?php $table->render_severity_filters( self::MENU_SLUG ); ?>
				<?php $table->display(); ?>
			</form>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"
			      onsubmit="return confirm('<?php echo esc_js( __( 'Permanently delete every activity log entry? This cannot be undone.', 'numeris-shield' ) ); ?>');"
			      style="margin-top:20px;">
				<input type="hidden" name="action" value="ns_clear_logs">
				<?php wp_nonce_field( 'ns_clear_logs' ); ?>
				<button type="submit" class="button"><?php esc_html_e( 'Clear all logs', 'numeris-shield' ); ?></button>
			</form>
		</div>
		<?php
	}

	public function handle_clear_logs() {
		if ( ! current_user_can( 'manage_options' ) || ! check_admin_referer( 'ns_clear_logs' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'numeris-shield' ) );
		}
		global $wpdb;
		$wpdb->query( 'TRUNCATE TABLE ' . NS_DB::log_table() ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- fixed internal table name, no user input
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::MENU_SLUG . '&cleared=1' ) );
		exit;
	}
}
