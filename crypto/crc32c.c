/*
 * Cryptographic API.
 *
 * CRC32C chksum
 *
 *@Article{castagnoli-crc,
 * author =       { Guy Castagnoli and Stefan Braeuer and Martin Herrman},
 * title =        {{Optimization of Cyclic Redundancy-Check Codes with 24
 *                 and 32 Parity Bits}},
 * journal =      IEEE Transactions on Communication,
 * year =         {1993},
 * volume =       {41},
 * number =       {6},
 * pages =        {},
 * month =        {June},
 *}
 * Used by the iSCSI driver, possibly others, and derived from the
 * the iscsi-crc.c module of the linux-iscsi driver at
 * http://linux-iscsi.sourceforge.net.
 *
 * Following the example of lib/crc32, this function is intended to be
 * flexible and useful for all users.  Modules that currently have their
 * own crc32c, but hopefully may be able to use this one are:
 *  net/sctp (please add all your doco to here if you change to
 *            use this one!)
 *  <endoflist>
 *
 * Copyright (c) 2004 Cisco Systems, Inc.
 * Copyright (c) 2008 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * The current crc32c implementation is adapted from Bob Pearson's slice-by-8
 * crc32 kernel patch from mid-2011.
 *
 * August 26, 2011 Darrick J. Wong <djwong at us.ibm.com>
 * Reuse Bob Pearson's slice-by-8 implementation for e2fsprogs.
 *
 * July 20, 2011 Bob Pearson <rpearson at systemfabricworks.com>
 * added slice by 8 algorithm to the existing conventional and
 * slice by 4 algorithms.
 *
 * Oct 15, 2000 Matt Domsch <Matt_Domsch@dell.com>
 * Nicer crc32 functions/docs submitted by linux@horizon.com.  Thanks!
 * Code was from the public domain, copyright abandoned.  Code was
 * subsequently included in the kernel, thus was re-licensed under the
 * GNU GPL v2.
 *
 * Oct 12, 2000 Matt Domsch <Matt_Domsch@dell.com>
 * Same crc32 function was used in 5 other places in the kernel.
 * I made one version, and deleted the others.
 * There are various incantations of crc32().  Some use a seed of 0 or ~0.
 * Some xor at the end with ~0.  The generic crc32() function takes
 * seed as an argument, and doesn't xor at the end.  Then individual
 * users can do whatever they need.
 *   drivers/net/smc9194.c uses seed ~0, doesn't xor with ~0.
 *   fs/jffs2 uses seed 0, doesn't xor with ~0.
 *   fs/partitions/efi.c uses seed ~0, xor's with ~0.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include "crc32c_defs.h"

#define CHKSUM_BLOCK_SIZE	1
#define CHKSUM_DIGEST_SIZE	4

struct chksum_ctx {
	u32 key;
};

struct chksum_desc_ctx {
	u32 crc;
};

#if CRC32C_BITS > 8
# define tole(x) (__force u32) __constant_cpu_to_le32(x)
#else
# define tole(x) (x)
#endif

#include "crc32c_table.h"

#if CRC32C_BITS == 32
/* slice by 4 algorithm */
static u32 crc32c_body(u32 crc, u8 const *buf, size_t len)
{
	const u8 *p8;
	const u32 *p32;
	size_t init_bytes;
	size_t words;
	size_t end_bytes;
	size_t i;
	u32 q;
	u8 i0, i1, i2, i3;

	crc = (__force u32) __cpu_to_le32(crc);

	/* unroll loop into 'init_bytes' odd bytes followed by
	 * 'words' aligned 4 byte words followed by
	 * 'end_bytes' odd bytes at the end */
	p8 = buf;
	p32 = (u32 *)PTR_ALIGN(p8, 4);
	init_bytes = min((uintptr_t)p32 - (uintptr_t)p8, len);
	words = (len - init_bytes) >> 2;
	end_bytes = (len - init_bytes) & 3;

	for (i = 0; i < init_bytes; i++) {
#ifdef __LITTLE_ENDIAN
		i0 = *p8++ ^ crc;
		crc = t0_le[i0] ^ (crc >> 8);
#else
		i0 = *p8++ ^ (crc >> 24);
		crc = t0_le[i0] ^ (crc << 8);
#endif
	}

	/* using pre-increment below slightly faster */
	p32--;

	for (i = 0; i < words; i++) {
#ifdef __LITTLE_ENDIAN
		q = *++p32 ^ crc;
		i3 = q;
		i2 = q >> 8;
		i1 = q >> 16;
		i0 = q >> 24;
		crc = t3_le[i3] ^ t2_le[i2] ^ t1_le[i1] ^ t0_le[i0];
#else
		q = *++p32 ^ crc;
		i3 = q >> 24;
		i2 = q >> 16;
		i1 = q >> 8;
		i0 = q;
		crc = t3_le[i3] ^ t2_le[i2] ^ t1_le[i1] ^ t0_le[i0];
#endif
	}

	p8 = (u8 *)(++p32);

	for (i = 0; i < end_bytes; i++) {
#ifdef __LITTLE_ENDIAN
		i0 = *p8++ ^ crc;
		crc = t0_le[i0] ^ (crc >> 8);
#else
		i0 = *p8++ ^ (crc >> 24);
		crc = t0_le[i0] ^ (crc << 8);
#endif
	}

	return __le32_to_cpu((__force __le32)crc);
}
#endif

#if CRC32C_BITS == 64
/* slice by 8 algorithm */
static u32 crc32c_body(u32 crc, u8 const *buf, size_t len)
{
	const u8 *p8;
	const u32 *p32;
	size_t init_bytes;
	size_t words;
	size_t end_bytes;
	size_t i;
	u32 q;
	u8 i0, i1, i2, i3;

	crc = (__force u32) __cpu_to_le32(crc);

	p8 = buf;
	p32 = (u32 *)PTR_ALIGN(p8, 8);
	i = (void *)p32 - (void *)p8;
	init_bytes = min(i, len);
	words = (len - init_bytes) >> 3;
	end_bytes = (len - init_bytes) & 7;

	for (i = 0; i < init_bytes; i++) {
#ifdef __LITTLE_ENDIAN
		i0 = *p8++ ^ crc;
		crc = t0_le[i0] ^ (crc >> 8);
#else
		i0 = *p8++ ^ (crc >> 24);
		crc = t0_le[i0] ^ (crc << 8);
#endif
	}

	p32--;

	for (i = 0; i < words; i++) {
#ifdef __LITTLE_ENDIAN
		q = *++p32 ^ crc;
		i3 = q;
		i2 = q >> 8;
		i1 = q >> 16;
		i0 = q >> 24;
		crc = t7_le[i3] ^ t6_le[i2] ^ t5_le[i1] ^ t4_le[i0];

		q = *++p32;
		i3 = q;
		i2 = q >> 8;
		i1 = q >> 16;
		i0 = q >> 24;
		crc ^= t3_le[i3] ^ t2_le[i2] ^ t1_le[i1] ^ t0_le[i0];
#else
		q = *++p32 ^ crc;
		i3 = q >> 24;
		i2 = q >> 16;
		i1 = q >> 8;
		i0 = q;
		crc = t7_le[i3] ^ t6_le[i2] ^ t5_le[i1] ^ t4_le[i0];

		q = *++p32;
		i3 = q >> 24;
		i2 = q >> 16;
		i1 = q >> 8;
		i0 = q;
		crc ^= t3_le[i3] ^ t2_le[i2] ^ t1_le[i1] ^ t0_le[i0];
#endif
	}

	p8 = (u8 *)(++p32);

	for (i = 0; i < end_bytes; i++) {
#ifdef __LITTLE_ENDIAN
		i0 = *p8++ ^ crc;
		crc = t0_le[i0] ^ (crc >> 8);
#else
		i0 = *p8++ ^ (crc >> 24);
		crc = t0_le[i0] ^ (crc << 8);
#endif
	}

	return __le32_to_cpu(crc);
}
#endif

/**
 * crc32c() - Calculate bitwise little-endian CRC32c.
 * @crc: seed value for computation.  ~0 for ext4, sometimes 0 for
 *	other uses, or the previous crc32c value if computing incrementally.
 * @p: pointer to buffer over which CRC is run
 * @len: length of buffer @p
 */
static u32 crc32c(u32 crc, unsigned char const *p, size_t len)
{
#if CRC32C_BITS == 1
	int i;
	while (len--) {
		crc ^= *p++;
		for (i = 0; i < 8; i++)
			crc = (crc >> 1) ^ ((crc & 1) ? CRC32C_POLY_LE : 0);
	}
# elif CRC32C_BITS == 2
	while (len--) {
		crc ^= *p++;
		crc = (crc >> 2) ^ t0_le[crc & 0x03];
		crc = (crc >> 2) ^ t0_le[crc & 0x03];
		crc = (crc >> 2) ^ t0_le[crc & 0x03];
		crc = (crc >> 2) ^ t0_le[crc & 0x03];
	}
# elif CRC32C_BITS == 4
	while (len--) {
		crc ^= *p++;
		crc = (crc >> 4) ^ t0_le[crc & 0x0f];
		crc = (crc >> 4) ^ t0_le[crc & 0x0f];
	}
# elif CRC32C_BITS == 8
	while (len--) {
		crc ^= *p++;
		crc = (crc >> 8) ^ t0_le[crc & 0xff];
	}
# else
	crc = crc32c_body(crc, p, len);
# endif
	return crc;
}

/*
 * Steps through buffer one byte at at time, calculates reflected
 * crc using table.
 */

static int chksum_init(struct shash_desc *desc)
{
	struct chksum_ctx *mctx = crypto_shash_ctx(desc->tfm);
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	ctx->crc = mctx->key;

	return 0;
}

/*
 * Setting the seed allows arbitrary accumulators and flexible XOR policy
 * If your algorithm starts with ~0, then XOR with ~0 before you set
 * the seed.
 */
static int chksum_setkey(struct crypto_shash *tfm, const u8 *key,
			 unsigned int keylen)
{
	struct chksum_ctx *mctx = crypto_shash_ctx(tfm);

	if (keylen != sizeof(mctx->key)) {
		crypto_shash_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}
	mctx->key = le32_to_cpu(*(__le32 *)key);
	return 0;
}

static int chksum_update(struct shash_desc *desc, const u8 *data,
			 unsigned int length)
{
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	ctx->crc = crc32c(ctx->crc, data, length);
	return 0;
}

static int chksum_final(struct shash_desc *desc, u8 *out)
{
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	*(__le32 *)out = ~cpu_to_le32p(&ctx->crc);
	return 0;
}

static int __chksum_finup(u32 *crcp, const u8 *data, unsigned int len, u8 *out)
{
	*(__le32 *)out = ~cpu_to_le32(crc32c(*crcp, data, len));
	return 0;
}

static int chksum_finup(struct shash_desc *desc, const u8 *data,
			unsigned int len, u8 *out)
{
	struct chksum_desc_ctx *ctx = shash_desc_ctx(desc);

	return __chksum_finup(&ctx->crc, data, len, out);
}

static int chksum_digest(struct shash_desc *desc, const u8 *data,
			 unsigned int length, u8 *out)
{
	struct chksum_ctx *mctx = crypto_shash_ctx(desc->tfm);

	return __chksum_finup(&mctx->key, data, length, out);
}

static int crc32c_cra_init(struct crypto_tfm *tfm)
{
	struct chksum_ctx *mctx = crypto_tfm_ctx(tfm);

	mctx->key = ~0;
	return 0;
}

static struct shash_alg alg = {
	.digestsize		=	CHKSUM_DIGEST_SIZE,
	.setkey			=	chksum_setkey,
	.init   		= 	chksum_init,
	.update 		=	chksum_update,
	.final  		=	chksum_final,
	.finup  		=	chksum_finup,
	.digest  		=	chksum_digest,
	.descsize		=	sizeof(struct chksum_desc_ctx),
	.base			=	{
		.cra_name		=	"crc32c",
		.cra_driver_name	=	"crc32c-generic",
		.cra_priority		=	100,
		.cra_blocksize		=	CHKSUM_BLOCK_SIZE,
		.cra_alignmask		=	3,
		.cra_ctxsize		=	sizeof(struct chksum_ctx),
		.cra_module		=	THIS_MODULE,
		.cra_init		=	crc32c_cra_init,
	}
};

static int __init crc32c_mod_init(void)
{
	return crypto_register_shash(&alg);
}

static void __exit crc32c_mod_fini(void)
{
	crypto_unregister_shash(&alg);
}

module_init(crc32c_mod_init);
module_exit(crc32c_mod_fini);

MODULE_AUTHOR("Clay Haapala <chaapala@cisco.com>");
MODULE_DESCRIPTION("CRC32c (Castagnoli) calculations wrapper for lib/crc32c");
MODULE_LICENSE("GPL");
