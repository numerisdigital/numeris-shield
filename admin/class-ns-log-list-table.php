<?php
/**
 * Paginated, severity-filterable activity log table. Extends WordPress's
 * own WP_List_Table so it gets native-feeling sorting/pagination chrome
 * for free instead of a hand-rolled table.
 */

defined( 'ABSPATH' ) || exit;

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

class NS_Log_List_Table extends WP_List_Table {

	const PER_PAGE = 20;

	public function __construct() {
		parent::__construct( array(
			'singular' => 'log-entry',
			'plural'   => 'log-entries',
			'ajax'     => false,
		) );
	}

	public function get_columns() {
		return array(
			'created_at' => __( 'Time', 'numeris-shield' ),
			'severity'   => __( 'Severity', 'numeris-shield' ),
			'message'    => __( 'Event', 'numeris-shield' ),
			'username'   => __( 'User', 'numeris-shield' ),
			'ip_address' => __( 'IP Address', 'numeris-shield' ),
		);
	}

	/**
	 * Renders the "All / Info / Warning / Critical" filter tabs, each a
	 * plain link carrying ?severity=x — a full page reload rather than
	 * JS, so this works identically with or without JavaScript.
	 */
	public function render_severity_filters( $menu_slug ) {
		$current = isset( $_GET['severity'] ) ? sanitize_key( $_GET['severity'] ) : '';
		$counts  = $this->get_severity_counts();

		$levels = array(
			''         => __( 'All', 'numeris-shield' ),
			'info'     => __( 'Info', 'numeris-shield' ),
			'warning'  => __( 'Warning', 'numeris-shield' ),
			'critical' => __( 'Critical', 'numeris-shield' ),
		);

		echo '<ul class="subsubsub">';
		$items = array();
		foreach ( $levels as $key => $label ) {
			$count = '' === $key ? array_sum( $counts ) : ( $counts[ $key ] ?? 0 );
			$url   = $key ? add_query_arg( array( 'page' => $menu_slug, 'severity' => $key ), admin_url( 'admin.php' ) ) : add_query_arg( array( 'page' => $menu_slug ), admin_url( 'admin.php' ) );
			$class = ( $current === $key ) ? ' class="current"' : '';
			$items[] = sprintf(
				'<li><a href="%s"%s>%s <span class="count">(%d)</span></a></li>',
				esc_url( $url ),
				$class,
				esc_html( $label ),
				(int) $count
			);
		}
		echo implode( ' | ', $items );
		echo '</ul>';
	}

	private function get_severity_counts() {
		global $wpdb;
		$table   = NS_DB::log_table();
		$results = $wpdb->get_results( "SELECT severity, COUNT(*) as c FROM {$table} GROUP BY severity", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name only, no user input
		$counts  = array( 'info' => 0, 'warning' => 0, 'critical' => 0 );
		foreach ( (array) $results as $row ) {
			if ( isset( $counts[ $row['severity'] ] ) ) {
				$counts[ $row['severity'] ] = (int) $row['c'];
			}
		}
		return $counts;
	}

	public function prepare_items() {
		global $wpdb;
		$table = NS_DB::log_table();

		$severity = isset( $_GET['severity'] ) ? sanitize_key( $_GET['severity'] ) : '';
		$where    = '';
		$params   = array();
		if ( in_array( $severity, array( 'info', 'warning', 'critical' ), true ) ) {
			$where    = 'WHERE severity = %s';
			$params[] = $severity;
		}

		$per_page     = self::PER_PAGE;
		$current_page = $this->get_pagenum();
		$offset       = ( $current_page - 1 ) * $per_page;

		$count_sql   = "SELECT COUNT(*) FROM {$table} {$where}"; // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name only; $where's own placeholders are prepared below.
		$total_items = $params ? (int) $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ) : (int) $wpdb->get_var( $count_sql );

		$sql          = "SELECT * FROM {$table} {$where} ORDER BY id DESC LIMIT %d OFFSET %d"; // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$query_params = array_merge( $params, array( $per_page, $offset ) );
		$this->items  = $wpdb->get_results( $wpdb->prepare( $sql, $query_params ), ARRAY_A );

		$this->set_pagination_args( array(
			'total_items' => $total_items,
			'per_page'    => $per_page,
			'total_pages' => (int) ceil( $total_items / $per_page ),
		) );

		$this->_column_headers = array( $this->get_columns(), array(), array() );
	}

	public function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'created_at':
				return esc_html( get_date_from_gmt( $item['created_at'], 'Y-m-d H:i:s' ) );
			case 'severity':
				return $this->severity_badge( $item['severity'] );
			case 'message':
				return esc_html( $item['message'] );
			case 'username':
				return $item['username'] ? esc_html( $item['username'] ) : '—';
			case 'ip_address':
				return $item['ip_address'] ? esc_html( $item['ip_address'] ) : '—';
			default:
				return '';
		}
	}

	private function severity_badge( $severity ) {
		$styles = array(
			'info'     => array( '#e0edff', '#1d4ed8' ),
			'warning'  => array( '#fef3c7', '#92400e' ),
			'critical' => array( '#fee2e2', '#991b1b' ),
		);
		$style = $styles[ $severity ] ?? array( '#f0f0f1', '#3c434a' );
		return sprintf(
			'<span style="display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.02em;background:%s;color:%s;">%s</span>',
			esc_attr( $style[0] ),
			esc_attr( $style[1] ),
			esc_html( ucfirst( $severity ) )
		);
	}

	public function no_items() {
		esc_html_e( 'No activity logged yet.', 'numeris-shield' );
	}
}
