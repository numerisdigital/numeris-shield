<?php
/**
 * Self-hosted updates via GitHub Releases, since this plugin isn't (and
 * won't be) distributed through wordpress.org. Hooking into the same
 * update_plugins transient and plugins_api filter that WordPress core uses
 * for its own updates means the "update available" notice, the one-click
 * "Update now" link, and any external tool that reads those same standard
 * transients (WP Umbrella, ManageWP, MainWP, etc.) all pick this up
 * automatically — nothing tool-specific to build.
 */

defined( 'ABSPATH' ) || exit;

class NS_GitHub_Updater {

	const REPO      = 'numerisdigital/numeris-shield';
	const CACHE_KEY = 'ns_github_update_check';

	public function __construct() {
		add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'check_for_update' ) );
		add_filter( 'plugins_api', array( $this, 'plugin_info' ), 20, 3 );
		add_filter( 'upgrader_source_selection', array( $this, 'fix_source_folder_name' ), 10, 4 );
		add_action( 'upgrader_process_complete', array( $this, 'purge_cache' ), 10, 2 );
		add_action( 'delete_site_transient_update_plugins', array( $this, 'purge_cache' ) );
	}

	private function plugin_file() {
		return plugin_basename( NS_FILE );
	}

	/**
	 * The installed folder name, read at runtime rather than assumed —
	 * this plugin isn't always installed under the literal "numeris-shield"
	 * folder (e.g. a GitHub "Download ZIP" extracts as "numeris-shield-main"),
	 * and the folder WordPress needs the update package renamed to must
	 * match whatever is actually on disk on that specific site.
	 */
	private function plugin_slug() {
		return dirname( $this->plugin_file() );
	}

	/**
	 * Latest GitHub release, cached in a transient to stay well within
	 * GitHub's unauthenticated API rate limit (60 requests/hour per IP —
	 * fine now the repo is public, but still worth not hitting on every
	 * single page load).
	 */
	private function get_latest_release() {
		$cached = get_transient( self::CACHE_KEY );
		if ( false !== $cached ) {
			return $cached;
		}

		$response = wp_remote_get( 'https://api.github.com/repos/' . self::REPO . '/releases/latest', array(
			'headers' => array(
				'Accept'     => 'application/vnd.github+json',
				'User-Agent' => 'NumerisShield-Updater',
			),
			'timeout' => 10,
		) );

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			// Short backoff before retrying, so a GitHub outage or rate
			// limit doesn't turn into a request on every single page load.
			set_transient( self::CACHE_KEY, array(), 15 * MINUTE_IN_SECONDS );
			return array();
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || empty( $data['tag_name'] ) ) {
			set_transient( self::CACHE_KEY, array(), 15 * MINUTE_IN_SECONDS );
			return array();
		}

		set_transient( self::CACHE_KEY, $data, 6 * HOUR_IN_SECONDS );
		return $data;
	}

	/**
	 * Injects an update-available entry into the same transient WordPress
	 * core populates from wordpress.org, if the latest GitHub release is
	 * newer than what's installed.
	 */
	public function check_for_update( $transient ) {
		if ( empty( $transient->checked ) ) {
			return $transient;
		}

		$release = $this->get_latest_release();
		if ( empty( $release['tag_name'] ) ) {
			return $transient;
		}

		$remote_version = ltrim( $release['tag_name'], 'v' );
		$plugin_file    = $this->plugin_file();
		$installed      = $transient->checked[ $plugin_file ] ?? NS_VERSION;

		if ( version_compare( $remote_version, $installed, '>' ) ) {
			$transient->response[ $plugin_file ] = (object) array(
				'slug'        => $this->plugin_slug(),
				'plugin'      => $plugin_file,
				'new_version' => $remote_version,
				'url'         => 'https://github.com/' . self::REPO,
				'package'     => $release['zipball_url'],
				'tested'      => get_bloginfo( 'version' ),
			);
			unset( $transient->no_update[ $plugin_file ] );
		} else {
			unset( $transient->response[ $plugin_file ] );
		}

		return $transient;
	}

	/**
	 * Populates the "View details" popup on the Plugins page with the
	 * GitHub release's own description/changelog.
	 */
	public function plugin_info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || empty( $args->slug ) || $this->plugin_slug() !== $args->slug ) {
			return $result;
		}

		$release = $this->get_latest_release();
		if ( empty( $release['tag_name'] ) ) {
			return $result;
		}

		return (object) array(
			'name'          => 'Numeris Shield',
			'slug'          => $this->plugin_slug(),
			'version'       => ltrim( $release['tag_name'], 'v' ),
			'author'        => '<a href="https://numeris.digital">Numeris Digital</a>',
			'homepage'      => 'https://github.com/' . self::REPO,
			'sections'      => array(
				'description' => 'Login hardening, brute-force protection, two-factor authentication, core hardening and activity logging for WordPress.',
				'changelog'   => wpautop( wp_kses_post( $release['body'] ?? 'No changelog provided.' ) ),
			),
			'download_link' => $release['zipball_url'],
		);
	}

	/**
	 * GitHub's auto-generated release zip extracts to a folder named after
	 * the repo/commit (e.g. numerisdigital-numeris-shield-a1b2c3d), not this
	 * site's actual plugin folder — WordPress needs the extracted folder
	 * renamed to match, or the update installs alongside the existing copy
	 * instead of replacing it.
	 */
	public function fix_source_folder_name( $source, $remote_source, $upgrader, $hook_extra = array() ) {
		if ( empty( $hook_extra['plugin'] ) || $this->plugin_file() !== $hook_extra['plugin'] ) {
			return $source;
		}

		global $wp_filesystem;

		$target = trailingslashit( $remote_source ) . $this->plugin_slug() . '/';
		if ( trailingslashit( $source ) === $target ) {
			return $source;
		}

		if ( $wp_filesystem->move( $source, $target ) ) {
			return $target;
		}

		return $source;
	}

	/**
	 * Drops the cached release data once an update actually runs (whether
	 * ours or another plugin's — cheap to check) or an admin clicks "Check
	 * Again" on the Plugins page, so a fresh release is reflected
	 * immediately rather than waiting out the cache window.
	 */
	public function purge_cache( $upgrader = null, $options = array() ) {
		if ( null === $upgrader || ( isset( $options['action'], $options['type'] ) && 'update' === $options['action'] && 'plugin' === $options['type'] ) ) {
			delete_transient( self::CACHE_KEY );
		}
	}
}
