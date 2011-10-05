#include <stdio.h>
#include "crc32c_defs.h"
#include <inttypes.h>

#define ENTRIES_PER_LINE 4

#if CRC32C_BITS <= 8
#define LE_TABLE_SIZE (1 << CRC32C_BITS)
#else
#define LE_TABLE_SIZE 256
#endif

static uint32_t crc32c_table[8][256];

/**
 * crc32c_init() - allocate and initialize LE table data
 *
 * crc is the crc of the byte i; other entries are filled in based on the
 * fact that crctable[i^j] = crctable[i] ^ crctable[j].
 *
 */
static void crc32c_init(void)
{
	unsigned i, j;
	uint32_t crc = 1;

	crc32c_table[0][0] = 0;

	for (i = LE_TABLE_SIZE >> 1; i; i >>= 1) {
		crc = (crc >> 1) ^ ((crc & 1) ? CRC32C_POLY_LE : 0);
		for (j = 0; j < LE_TABLE_SIZE; j += 2 * i)
			crc32c_table[0][i + j] = crc ^ crc32c_table[0][j];
	}
	for (i = 0; i < LE_TABLE_SIZE; i++) {
		crc = crc32c_table[0][i];
		for (j = 1; j < 8; j++) {
			crc = crc32c_table[0][crc & 0xff] ^ (crc >> 8);
			crc32c_table[j][i] = crc;
		}
	}
}

static void output_table(uint32_t table[8][256], int len, char trans)
{
	int i, j;

	for (j = 0 ; j < 8; j++) {
		printf("static const u32 t%d_%ce[] = {", j, trans);
		for (i = 0; i < len - 1; i++) {
			if ((i % ENTRIES_PER_LINE) == 0)
				printf("\n");
			printf("to%ce(0x%8.8xL),", trans, table[j][i]);
			if ((i % ENTRIES_PER_LINE) != (ENTRIES_PER_LINE - 1))
				printf(" ");
		}
		printf("to%ce(0x%8.8xL)};\n\n", trans, table[j][len - 1]);

		if ((j+1)*8 >= CRC32C_BITS)
			break;
	}
}

int main(int argc, char **argv)
{
	printf("/*\n");
	printf(" * crc32c_table.h - CRC32c tables\n");
	printf(" *    this file is generated - do not edit\n");
	printf(" *	# gen_crc32ctable > crc32c_table.h\n");
	printf(" *    with\n");
	printf(" *	CRC32C_BITS = %d\n", CRC32C_BITS);
	printf(" */\n");

	if (CRC32C_BITS > 1) {
		crc32c_init();
		output_table(crc32c_table, LE_TABLE_SIZE, 'l');
	}

	return 0;
}
