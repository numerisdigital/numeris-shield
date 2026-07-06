<?php
/**
 * TOTP (RFC 6238) / HOTP (RFC 4226) algorithm implementation, plus backup
 * codes. Pure algorithm only — no WordPress hooks, no storage. NS_Two_Factor
 * is what actually wires this up to user accounts and the login flow.
 *
 * The HOTP/TOTP math here is verified against the official RFC 6238
 * Appendix B test vectors (see the plugin's dev notes) — those are
 * published, independently-checkable values, which is as close to
 * objective proof of correctness as this kind of code gets without a
 * physical device to scan against.
 */

defined( 'ABSPATH' ) || exit;

class NS_TOTP {

	const PERIOD = 30;
	const DIGITS = 6;

	/**
	 * A fresh random secret, 20 bytes (160 bits) — the size every major
	 * authenticator app expects — returned base32-encoded, since that's
	 * the conventional wire format for TOTP secrets (what you'd type in
	 * manually, and what goes in the otpauth:// URI).
	 */
	public static function generate_secret() {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * The otpauth:// URI a QR code / authenticator app deep link encodes.
	 * Issuer appears both in the path (for older app compatibility) and
	 * as its own query param (the modern, unambiguous way), per Google's
	 * "Key Uri Format" convention that all major apps follow.
	 */
	public static function get_otpauth_uri( $secret_base32, $account_label, $issuer ) {
		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $account_label );
		$query = http_build_query( array(
			'secret'    => $secret_base32,
			'issuer'    => $issuer,
			'algorithm' => 'SHA1',
			'digits'    => self::DIGITS,
			'period'    => self::PERIOD,
		), '', '&', PHP_QUERY_RFC3986 );

		return "otpauth://totp/{$label}?{$query}";
	}

	/**
	 * A shorter otpauth:// URI for the QR code specifically — secret only,
	 * relying on the label prefix to identify the issuer/account and on
	 * every major authenticator app defaulting to SHA1/6-digit/30s when
	 * those params are absent. NS_QR_Encoder only reliably supports
	 * versions 1–5 (~106 bytes at ECC level L); the full explicit URI from
	 * get_otpauth_uri() comfortably exceeds that for realistic site domains
	 * and usernames, so the QR image uses this instead while the "tap to
	 * open" link/manual fallback still uses the fully explicit version.
	 */
	public static function get_otpauth_uri_minimal( $secret_base32, $account_label, $issuer ) {
		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $account_label );
		return "otpauth://totp/{$label}?secret={$secret_base32}";
	}

	/** Manual entry key, grouped in 4-character blocks for readability. */
	public static function format_secret_for_display( $secret_base32 ) {
		return trim( chunk_split( $secret_base32, 4, ' ' ) );
	}

	/**
	 * Checks a submitted 6-digit code against the secret, tolerating clock
	 * drift by also accepting the previous/next time step ($window on each
	 * side of "now"). hash_equals() specifically to avoid a timing attack
	 * distinguishing "close" from "wrong" codes.
	 */
	public static function verify_code( $secret_base32, $code, $window = 1 ) {
		$code = preg_replace( '/\s+/', '', (string) $code );
		if ( '' === $code ) {
			return false;
		}

		$now = time();
		for ( $i = -$window; $i <= $window; $i++ ) {
			$candidate = self::generate_code( $secret_base32, $now + ( $i * self::PERIOD ) );
			if ( hash_equals( $candidate, $code ) ) {
				return true;
			}
		}
		return false;
	}

	public static function generate_code( $secret_base32, $timestamp = null ) {
		$timestamp = $timestamp ?? time();
		$counter   = (int) floor( $timestamp / self::PERIOD );
		return self::hotp( self::base32_decode( $secret_base32 ), $counter );
	}

	/**
	 * HOTP per RFC 4226 §5.3: HMAC-SHA1 of the 8-byte big-endian counter,
	 * then "dynamic truncation" — take a 4-byte window starting at an
	 * offset taken from the hash's own last nibble, mask off the top bit
	 * (keeps the result positive when read as a signed 32-bit int on
	 * platforms that care), then reduce mod 10^digits.
	 */
	private static function hotp( $secret_binary, $counter, $digits = self::DIGITS ) {
		$counter_bytes = '';
		for ( $i = 7; $i >= 0; $i-- ) {
			$counter_bytes .= chr( ( $counter >> ( $i * 8 ) ) & 0xFF );
		}

		$hash   = hash_hmac( 'sha1', $counter_bytes, $secret_binary, true );
		$offset = ord( $hash[19] ) & 0x0F;

		$code = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xFF );

		$code = $code % ( 10 ** $digits );
		return str_pad( (string) $code, $digits, '0', STR_PAD_LEFT );
	}

	/* ── Base32 (RFC 4648 §6) — no external dependency for this ──────── */

	public static function base32_encode( $data ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$binary   = '';
		foreach ( str_split( $data ) as $char ) {
			$binary .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}

		$encoded = '';
		foreach ( str_split( $binary, 5 ) as $chunk ) {
			$chunk    = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			$encoded .= $alphabet[ bindec( $chunk ) ];
		}
		return $encoded;
	}

	public static function base32_decode( $data ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$data     = rtrim( strtoupper( trim( (string) $data ) ), '=' );

		$binary = '';
		foreach ( str_split( $data ) as $char ) {
			$pos = strpos( $alphabet, $char );
			if ( false === $pos ) {
				continue; // Skip anything a user might paste in by mistake (spaces already trimmed elsewhere).
			}
			$binary .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}

		$bytes = '';
		foreach ( str_split( $binary, 8 ) as $byte ) {
			if ( strlen( $byte ) < 8 ) {
				break; // Trailing partial byte from base32 padding — not real data.
			}
			$bytes .= chr( bindec( $byte ) );
		}
		return $bytes;
	}

	/* ── Backup codes ─────────────────────────────────────────────────── */

	/**
	 * Plain-text codes to show the user once (format: xxxx-xxxx, easy to
	 * read/type). Callers are responsible for hashing before storage —
	 * see NS_Two_Factor, which stores only the hashes.
	 */
	public static function generate_backup_codes( $count ) {
		$codes = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$codes[] = wp_generate_password( 4, false, false ) . '-' . wp_generate_password( 4, false, false );
		}
		return $codes;
	}

	public static function hash_backup_code( $code ) {
		return password_hash( self::normalize_backup_code( $code ), PASSWORD_DEFAULT );
	}

	public static function verify_backup_code( $code, $hash ) {
		return password_verify( self::normalize_backup_code( $code ), $hash );
	}

	private static function normalize_backup_code( $code ) {
		return strtoupper( preg_replace( '/[^a-zA-Z0-9]/', '', (string) $code ) );
	}
}
