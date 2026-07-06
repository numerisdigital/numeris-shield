<?php
/**
 * Minimal QR Code encoder (ISO/IEC 18004), byte mode only, error
 * correction level L, versions 1–5 (no multi-block interleaving needed at
 * that range, which removes the most error-prone part of the standard).
 *
 * This exists so the plugin never has to send a 2FA secret to a
 * third-party QR-generation API — the whole thing is generated locally
 * from data that's already on the page.
 *
 * GF(256) arithmetic tables and the Reed–Solomon generator polynomial are
 * computed at runtime from the standard's defining polynomial (0x11D)
 * rather than hand-copied from a table, which removes an entire class of
 * transcription bugs. After encoding, self_check() independently
 * recomputes the Reed–Solomon syndromes for the final codeword sequence;
 * if they're not all zero, something is wrong and the caller should not
 * render the result — see NS_QR_Encoder::encode()'s return value.
 *
 * If the payload is too long for version 5 at level L (~106 bytes), this
 * intentionally does not fall back to a larger version, since that would
 * require the multi-block interleaving this implementation deliberately
 * avoids for reliability. NS_Two_Factor handles that case by omitting the
 * QR image and relying on the manual entry key instead.
 */

defined( 'ABSPATH' ) || exit;

class NS_QR_Encoder {

	/** Data codewords available at ECC level L for versions 1–5 (single block, no interleaving). */
	private static $capacity = array(
		1 => array( 'total' => 26, 'ec' => 7, 'data' => 19 ),
		2 => array( 'total' => 44, 'ec' => 10, 'data' => 34 ),
		3 => array( 'total' => 70, 'ec' => 15, 'data' => 55 ),
		4 => array( 'total' => 100, 'ec' => 20, 'data' => 80 ),
		5 => array( 'total' => 134, 'ec' => 26, 'data' => 108 ),
	);

	/** Single alignment-pattern center per version (none for v1). */
	private static $alignment_center = array( 2 => 18, 3 => 22, 4 => 26, 5 => 30 );

	private static $gf_exp = array();
	private static $gf_log = array();

	/**
	 * @return array{ok:bool, size:int, matrix:array<array<bool>>}|array{ok:false}
	 */
	public static function encode( $text ) {
		self::init_gf_tables();

		$bytes = array_values( unpack( 'C*', $text ) );
		$version = self::pick_version( count( $bytes ) );
		if ( null === $version ) {
			return array( 'ok' => false );
		}

		$cap = self::$capacity[ $version ];
		$data_codewords = self::build_data_codewords( $bytes, $cap['data'] );
		$ec_codewords   = self::reed_solomon_encode( $data_codewords, $cap['ec'] );
		$all_codewords  = array_merge( $data_codewords, $ec_codewords );

		if ( ! self::self_check( $data_codewords, $ec_codewords, $cap['ec'] ) ) {
			return array( 'ok' => false );
		}

		$size   = 17 + 4 * $version;
		$matrix = self::build_matrix( $size, $version, $all_codewords );

		return array( 'ok' => true, 'size' => $size, 'matrix' => $matrix );
	}

	public static function to_svg( $result, $module_px = 6 ) {
		if ( empty( $result['ok'] ) ) {
			return '';
		}
		$size  = $result['size'];
		$px    = $size * $module_px;
		$quiet = $module_px * 4; // 4-module quiet zone border, per spec.
		$total = $px + ( $quiet * 2 );

		$rects = '';
		foreach ( $result['matrix'] as $y => $row ) {
			foreach ( $row as $x => $dark ) {
				if ( $dark ) {
					$rects .= sprintf(
						'<rect x="%d" y="%d" width="%d" height="%d"/>',
						$quiet + $x * $module_px,
						$quiet + $y * $module_px,
						$module_px,
						$module_px
					);
				}
			}
		}

		return sprintf(
			'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %1$d %1$d" width="%1$d" height="%1$d" shape-rendering="crispEdges"><rect width="%1$d" height="%1$d" fill="#fff"/><g fill="#000">%2$s</g></svg>',
			$total,
			$rects
		);
	}

	private static function pick_version( $byte_count ) {
		// Overhead: 4-bit mode indicator + 8-bit byte count + up to 4-bit terminator, rounded up.
		$overhead_bytes = 2;
		foreach ( self::$capacity as $version => $cap ) {
			if ( $byte_count + $overhead_bytes <= $cap['data'] ) {
				return $version;
			}
		}
		return null;
	}

	/**
	 * Mode indicator (byte mode = 0100) + 8-bit character count + data +
	 * terminator, byte-aligned, then padded with the standard alternating
	 * 0xEC/0x11 pad bytes up to the version's data codeword capacity.
	 */
	private static function build_data_codewords( array $bytes, $data_capacity ) {
		$bits = '0100' . str_pad( decbin( count( $bytes ) ), 8, '0', STR_PAD_LEFT );
		foreach ( $bytes as $byte ) {
			$bits .= str_pad( decbin( $byte ), 8, '0', STR_PAD_LEFT );
		}

		$bits .= str_repeat( '0', min( 4, max( 0, $data_capacity * 8 - strlen( $bits ) ) ) );
		if ( strlen( $bits ) % 8 !== 0 ) {
			$bits .= str_repeat( '0', 8 - ( strlen( $bits ) % 8 ) );
		}

		$codewords = array();
		foreach ( str_split( $bits, 8 ) as $byte_str ) {
			$codewords[] = bindec( $byte_str );
		}

		$pad = array( 0xEC, 0x11 );
		$i   = 0;
		while ( count( $codewords ) < $data_capacity ) {
			$codewords[] = $pad[ $i % 2 ];
			$i++;
		}

		return $codewords;
	}

	/* ── GF(256) arithmetic, generated from the standard's primitive polynomial ── */

	private static function init_gf_tables() {
		if ( ! empty( self::$gf_exp ) ) {
			return;
		}
		$x = 1;
		for ( $i = 0; $i < 255; $i++ ) {
			self::$gf_exp[ $i ] = $x;
			self::$gf_log[ $x ] = $i;
			$x <<= 1;
			if ( $x & 0x100 ) {
				$x ^= 0x11D; // QR's primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1.
			}
		}
		for ( $i = 255; $i < 512; $i++ ) {
			self::$gf_exp[ $i ] = self::$gf_exp[ $i - 255 ];
		}
	}

	private static function gf_mul( $a, $b ) {
		if ( 0 === $a || 0 === $b ) {
			return 0;
		}
		return self::$gf_exp[ self::$gf_log[ $a ] + self::$gf_log[ $b ] ];
	}

	/**
	 * The generator polynomial for $ec_count EC codewords is the standard
	 * product (x - α^0)(x - α^1)...(x - α^(n-1)) built up iteratively —
	 * computed here rather than looked up, so it's automatically correct
	 * for any EC codeword count instead of depending on a hand-copied
	 * per-version table of polynomial coefficients.
	 */
	private static function generator_polynomial( $ec_count ) {
		$poly = array( 1 );
		for ( $i = 0; $i < $ec_count; $i++ ) {
			$poly[] = 0;
			// Multiplying a monic polynomial by (x + a^i): the leading
			// coefficient (index 0) is untouched by this — a shift to the
			// next degree up carries the same leading term — only indices
			// 1.. shift/accumulate. (Verified by hand against a concrete
			// GF(256) example; an earlier version of this method had an
			// extra `$poly[0] = gf_mul(...)` line here that doesn't belong
			// and produced a wrong generator polynomial.)
			for ( $j = count( $poly ) - 1; $j > 0; $j-- ) {
				$poly[ $j ] = $poly[ $j ] ^ self::gf_mul( $poly[ $j - 1 ], self::$gf_exp[ $i ] );
			}
		}
		return $poly;
	}

	private static function reed_solomon_encode( array $data_codewords, $ec_count ) {
		$generator = self::generator_polynomial( $ec_count );
		$remainder = array_fill( 0, $ec_count, 0 );

		foreach ( $data_codewords as $codeword ) {
			$factor = $codeword ^ $remainder[0];
			array_shift( $remainder );
			$remainder[] = 0;
			for ( $i = 0; $i < $ec_count; $i++ ) {
				$remainder[ $i ] ^= self::gf_mul( $generator[ $i + 1 ], $factor );
			}
		}

		return $remainder;
	}

	/**
	 * Independent correctness check: a valid Reed–Solomon codeword,
	 * evaluated at every root α^i of the generator polynomial used to
	 * build it, must equal zero at all of them. This re-derives the roots
	 * from scratch and checks the *combined* data+EC codeword sequence
	 * against them — it isn't just re-running the same encode logic, it's
	 * verifying the mathematical property that definition guarantees.
	 */
	private static function self_check( array $data_codewords, array $ec_codewords, $ec_count ) {
		$full = array_merge( $data_codewords, $ec_codewords );
		$n    = count( $full );

		for ( $r = 0; $r < $ec_count; $r++ ) {
			$root = self::$gf_exp[ $r ];
			$acc  = 0;
			foreach ( $full as $i => $coefficient ) {
				$power = $n - 1 - $i;
				$acc  ^= self::gf_mul( $coefficient, self::gf_pow( $root, $power ) );
			}
			if ( 0 !== $acc ) {
				return false;
			}
		}
		return true;
	}

	private static function gf_pow( $base, $power ) {
		if ( 0 === $power ) {
			return 1;
		}
		return self::$gf_exp[ ( self::$gf_log[ $base ] * $power ) % 255 ];
	}

	/* ── Matrix construction ──────────────────────────────────────────── */

	private static function build_matrix( $size, $version, array $codewords ) {
		$matrix    = array_fill( 0, $size, array_fill( 0, $size, false ) );
		$reserved  = array_fill( 0, $size, array_fill( 0, $size, false ) );

		$mark = function ( $row, $col, $dark ) use ( &$matrix, &$reserved ) {
			$matrix[ $row ][ $col ]   = $dark;
			$reserved[ $row ][ $col ] = true;
		};

		$in_bounds = function ( $v ) use ( $size ) {
			return $v >= 0 && $v < $size;
		};

		$draw_finder = function ( $top, $left ) use ( &$mark, $in_bounds, $size ) {
			for ( $r = -1; $r <= 7; $r++ ) {
				$row = $top + $r;
				if ( ! $in_bounds( $row ) ) {
					continue;
				}
				for ( $c = -1; $c <= 7; $c++ ) {
					$col = $left + $c;
					if ( ! $in_bounds( $col ) ) {
						continue;
					}
					$is_border = ( 0 === $r || 6 === $r || 0 === $c || 6 === $c ) && $r >= 0 && $r <= 6 && $c >= 0 && $c <= 6;
					$is_core   = $r >= 2 && $r <= 4 && $c >= 2 && $c <= 4;
					$dark      = $is_border || $is_core;
					$mark( $row, $col, $dark );
				}
			}
		};

		$draw_finder( 0, 0 );
		$draw_finder( 0, $size - 7 );
		$draw_finder( $size - 7, 0 );

		// Timing patterns.
		for ( $i = 8; $i < $size - 8; $i++ ) {
			$dark = 0 === ( $i % 2 );
			$mark( 6, $i, $dark );
			$mark( $i, 6, $dark );
		}

		// Single alignment pattern (versions 2–5 only).
		if ( isset( self::$alignment_center[ $version ] ) ) {
			$center = self::$alignment_center[ $version ];
			for ( $r = -2; $r <= 2; $r++ ) {
				for ( $c = -2; $c <= 2; $c++ ) {
					$is_border = ( -2 === $r || 2 === $r || -2 === $c || 2 === $c );
					$is_center = ( 0 === $r && 0 === $c );
					$mark( $center + $r, $center + $c, $is_border || $is_center );
				}
			}
		}

		// Dark module, always present just below the bottom-left finder.
		$mark( 4 * $version + 9, 8, true );

		// Reserve format-info areas (content filled in once the mask is known).
		for ( $i = 0; $i <= 8; $i++ ) {
			if ( 6 !== $i ) {
				$reserved[8][ $i ]          = true;
				$reserved[ $i ][8]          = true;
			}
		}
		for ( $i = 0; $i < 8; $i++ ) {
			$reserved[8][ $size - 1 - $i ] = true;
			$reserved[ $size - 1 - $i ][8] = true;
		}
		$reserved[8][8] = true;

		// Zigzag data placement: two-column strips from the bottom-right,
		// moving upward then downward alternately, skipping the vertical
		// timing column (col 6).
		$bits = '';
		foreach ( $codewords as $codeword ) {
			$bits .= str_pad( decbin( $codeword ), 8, '0', STR_PAD_LEFT );
		}
		$bit_index = 0;
		$bit_total = strlen( $bits );

		$col     = $size - 1;
		$upward  = true;
		while ( $col > 0 ) {
			if ( 6 === $col ) {
				$col--;
			}
			$rows = $upward ? range( $size - 1, 0 ) : range( 0, $size - 1 );
			foreach ( $rows as $row ) {
				foreach ( array( $col, $col - 1 ) as $c ) {
					if ( $reserved[ $row ][ $c ] ) {
						continue;
					}
					$bit  = $bit_index < $bit_total ? ( '1' === $bits[ $bit_index ] ) : false;
					$bit_index++;
					// Mask pattern 0 (checkerboard) applied to data modules only.
					$masked = ( ( $row + $c ) % 2 === 0 ) ? ! $bit : $bit;
					$matrix[ $row ][ $c ] = $masked;
				}
			}
			$upward = ! $upward;
			$col   -= 2;
		}

		self::draw_format_info( $matrix, $size );

		return $matrix;
	}

	/**
	 * Format info: 2 bits ECC level (01 = L) + 3 bits mask pattern (000,
	 * matching mask 0 used above), BCH(15,5)-encoded and XORed with the
	 * fixed mask constant, then written into the two standard locations
	 * that both encode the same 15 bits (for redundancy).
	 */
	private static function draw_format_info( array &$matrix, $size ) {
		$format_value = 0b01000; // ECC level L = 01, mask pattern = 000.
		$bch          = self::bch_encode( $format_value, 0b10100110111, 10 );
		$bits         = $bch ^ 0b101010000010010;

		// Sequence position 0 corresponds to the MSB (bit 14) of the 15-bit
		// format string, descending to the LSB (bit 0) at position 14 — the
		// reverse of what a naive "$i-th bit" reading would give. Confirmed
		// against a known-good reference encoder's output; the original
		// version of this function read low-to-high and silently produced
		// a bit-reversed (and therefore invalid) format string, which is
		// why QR codes from an earlier build of this file scanned as
		// "detected" (finder patterns are fine) but failed to decode any
		// data (masking was applied using the wrong pattern once a real
		// scanner read the corrupted format info).
		$get_bit = function ( $i ) use ( $bits ) {
			return ( ( $bits >> ( 14 - $i ) ) & 1 ) === 1;
		};

		// Around the top-left finder.
		$sequence_a = array(
			array( 8, 0 ), array( 8, 1 ), array( 8, 2 ), array( 8, 3 ), array( 8, 4 ), array( 8, 5 ), array( 8, 7 ), array( 8, 8 ),
			array( 7, 8 ), array( 5, 8 ), array( 4, 8 ), array( 3, 8 ), array( 2, 8 ), array( 1, 8 ), array( 0, 8 ),
		);
		foreach ( $sequence_a as $i => $pos ) {
			$matrix[ $pos[0] ][ $pos[1] ] = $get_bit( $i );
		}

		// Split copy: bottom-left column and top-right row.
		for ( $i = 0; $i < 7; $i++ ) {
			$matrix[ $size - 1 - $i ][8] = $get_bit( $i );
		}
		for ( $i = 0; $i < 8; $i++ ) {
			$matrix[8][ $size - 8 + $i ] = $get_bit( 7 + $i );
		}
	}

	/**
	 * GF(2) polynomial division (i.e. with XOR instead of subtraction) —
	 * used for the format-info BCH code, independent of the GF(256) Reed–
	 * Solomon math above (different, smaller field: GF(2)).
	 */
	private static function bch_encode( $data, $generator, $ec_bits ) {
		$value = $data << $ec_bits;
		$msb   = function ( $v ) {
			return $v > 0 ? (int) floor( log( $v, 2 ) ) : -1;
		};
		$g_msb = $msb( $generator );
		while ( $msb( $value ) >= $ec_bits ) {
			$value ^= $generator << ( $msb( $value ) - $g_msb );
		}
		return ( $data << $ec_bits ) | $value;
	}
}
