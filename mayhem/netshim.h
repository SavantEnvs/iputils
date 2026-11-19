/* mayhem/netshim.h: see netshim.c. */
#ifndef MAYHEM_NETSHIM_H
#define MAYHEM_NETSHIM_H
#include <stddef.h>
#include <stdint.h>

#define NETSHIM_EOF_SILENT 0	/* end of input: a silent network (EAGAIN, waits time out) */
#define NETSHIM_EOF_SIGINT 1	/* end of input: Ctrl-C once, then silence */

void netshim_init(const uint8_t *data, size_t len, int eof_mode);
#endif
