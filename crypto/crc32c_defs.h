#ifndef CRC32C_DEFS_H_
#define CRC32C_DEFS_H_

/*
 * This is the CRC32c polynomial, as outlined by Castagnoli.
 * x^32+x^28+x^27+x^26+x^25+x^23+x^22+x^20+x^19+x^18+x^14+x^13+x^11+x^10+x^9+
 * x^8+x^6+x^0
 */
#define CRC32C_POLY_LE 0x82F63B78

/* How many bits at a time to use.  Valid values are 1, 2, 4, 8, 32 and 64. */
/* For less performance-sensitive, use 4 */
#ifdef CONFIG_CRC32C_SLICEBY8
# define CRC32C_BITS 64
#endif
#ifdef CONFIG_CRC32C_SLICEBY4
# define CRC32C_BITS 32
#endif
#ifdef CONFIG_CRC32C_SARWATE
# define CRC32C_BITS 8
#endif
#ifdef CONFIG_CRC32C_BIT
# define CRC32C_BITS 1
#endif

#ifndef CRC32C_BITS
# define CRC32C_BITS 64
#endif

/*
 * Little-endian CRC computation.  Used with serial bit streams sent
 * lsbit-first.  Be sure to use cpu_to_le32() to append the computed CRC.
 */
#if CRC32C_BITS > 64 || CRC32C_BITS < 1 || CRC32C_BITS == 16 || \
	CRC32C_BITS & CRC32C_BITS-1
# error "CRC32C_BITS must be one of {1, 2, 4, 8, 32, 64}"
#endif

#endif /* CRC32C_DEFS_H_ */
