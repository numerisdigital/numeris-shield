<?php
/**
 * Environment indicator: a small colored badge in the admin bar showing
 * Local / Staging / Production, so it's never ambiguous which environment
 * an admin is currently working in.
 *
 * Migrated from bespoke per-theme code (numeris theme's functions.php) so
 * it's available — and toggleable from one place — on every site this
 * plugin is installed on, rather than needing to be hand-copied into each
 * client theme individually.
 */

defined( 'ABSPATH' ) || exit;

class NS_Environment_Indicator {

	public function __construct() {
		if ( NUMERIS_SHIELD_DISABLE ) {
			return;
		}
		if ( ! NS_Settings::get( 'environment_indicator_enabled' ) ) {
			return;
		}
		add_action( 'admin_bar_menu', array( $this, 'add_admin_bar_node' ), 100 );
	}

	public function add_admin_bar_node( WP_Admin_Bar $bar ) {
		if ( ! is_admin_bar_showing() ) {
			return;
		}

		$environments = array(
			'local'      => array( 'label' => __( 'Local', 'numeris-shield' ), 'bg' => '#166534', 'color' => '#bbf7d0' ),
			'staging'    => array( 'label' => __( 'Staging', 'numeris-shield' ), 'bg' => '#92400e', 'color' => '#fde68a' ),
			'production' => array( 'label' => __( 'Production', 'numeris-shield' ), 'bg' => '#991b1b', 'color' => '#fecaca' ),
		);
		$cfg = $environments[ $this->detect_environment() ];

		$bar->add_node( array(
			'id'     => 'ns-environment',
			'parent' => 'top-secondary',
			'title'  => sprintf(
				'<span style="display:inline-flex;align-items:center;height:28px;background:%s;color:%s;border-radius:4px;padding:0 10px;font-size:11px;font-weight:700;letter-spacing:0.07em;text-transform:uppercase;">%s</span>',
				esc_attr( $cfg['bg'] ),
				esc_attr( $cfg['color'] ),
				esc_html( $cfg['label'] )
			),
			'meta'   => array( 'class' => 'ns-env-badge', 'tabindex' => '-1' ),
		) );
	}

	/**
	 * Prefers the WP_ENVIRONMENT_TYPE constant (the WordPress-native way
	 * to declare this, set in wp-config.php) when present, falling back
	 * to guessing from the site's hostname otherwise.
	 */
	private function detect_environment() {
		if ( defined( 'WP_ENVIRONMENT_TYPE' ) ) {
			$type = WP_ENVIRONMENT_TYPE;
			if ( in_array( $type, array( 'local', 'development' ), true ) ) {
				return 'local';
			}
			if ( 'staging' === $type ) {
				return 'staging';
			}
			return 'production';
		}

		// substr_compare()/strpos() rather than str_ends_with()/str_contains()
		// — those are PHP 8.0+ only, and this plugin declares PHP 7.4 as its
		// floor since it's installed on a mix of client sites.
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		if ( 0 === substr_compare( $host, '.local', -6 ) || 'localhost' === $host ) {
			return 'local';
		}
		if ( false !== strpos( $host, 'staging' ) || false !== strpos( $host, '.stg' ) || false !== strpos( $host, '-stg' ) ) {
			return 'staging';
		}
		return 'production';
	}
}
