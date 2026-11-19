/*
 * mayhem/fuzz_main.c — file-input driver: runs one iputils tool's real main() against a mock
 * network (netshim.c) whose received packets come from the input file.
 *
 *   <tool>_fuzz <input-file>
 *
 * Input: byte 0 picks the command line from the tool's table below (index modulo its size); the rest
 * is the sequence of packets the network delivers (record format: netshim.c). For the ping argument
 * target (TOOL_PING_ARGS) the input instead starts with up to 16 NUL-terminated arguments, ended by an
 * empty one, that are passed to ping before the fixed loopback destination.
 *
 * The tool runs as it does from a shell, so it exits through its own exit() paths.
 * Built once per tool with -DTOOL_<NAME>, and the tool's main renamed to tool_main.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "netshim.h"

int tool_main(int argc, char **argv);

#define MAXARGS 24

#if defined(TOOL_PING4)
#define PROG "ping"
#define EOF_MODE NETSHIM_EOF_SIGINT
static const char *const table[][MAXARGS] = {
	{ "-n", "-c", "3", "127.0.0.1" },
	{ "-n", "-v", "-c", "3", "127.0.0.1" },
	{ "-n", "-R", "-c", "2", "127.0.0.1" },
	{ "-n", "-T", "tsonly", "-c", "2", "127.0.0.1" },
	{ "-n", "-T", "tsandaddr", "-c", "2", "127.0.0.1" },
	{ "-n", "-f", "-c", "5", "127.0.0.1" },
	{ "-n", "-j", "-c", "2", "127.0.0.1" },
	{ "-n", "-s", "2000", "-c", "2", "127.0.0.1" },
	{ "-n", "-s", "0", "-c", "2", "127.0.0.1" },
	{ "-n", "-D", "-O", "-c", "3", "127.0.0.1" },
	{ "-n", "-A", "-c", "4", "127.0.0.1" },
	{ "-n", "-w", "3", "127.0.0.1" },
	{ "-n", "-b", "-c", "2", "255.255.255.255" },
	{ "-n", "-a", "-q", "-c", "3", "127.0.0.1" },
	{ "-n", "-l", "3", "-i", "0", "-c", "6", "127.0.0.1" },
	{ "-n", "-U", "-c", "2", "-p", "ff00", "127.0.0.1" },
};
#elif defined(TOOL_PING6)
#define PROG "ping"
#define EOF_MODE NETSHIM_EOF_SIGINT
static const char *const table[][MAXARGS] = {
	{ "-6", "-n", "-c", "3", "::1" },
	{ "-6", "-n", "-v", "-c", "3", "::1" },
	{ "-6", "-n", "-N", "name", "-c", "2", "::1" },
	{ "-6", "-n", "-N", "ipv6-all", "-c", "2", "::1" },
	{ "-6", "-n", "-N", "ipv4-all", "-c", "2", "::1" },
	{ "-6", "-n", "-N", "subject-ipv6=::1", "-N", "ipv6", "-c", "2", "::1" },
	{ "-6", "-n", "-N", "subject-name=example.org", "-N", "fqdn", "-c", "2", "::1" },
	{ "-6", "-n", "-j", "-c", "2", "::1" },
	{ "-6", "-n", "-f", "-c", "5", "::1" },
	{ "-6", "-n", "-s", "2000", "-c", "2", "::1" },
	{ "-6", "-n", "-D", "-O", "-c", "3", "::1" },
	{ "-6", "-n", "-F", "12345", "-c", "2", "::1" },
};
#elif defined(TOOL_PING_ARGS)
#define PROG "ping"
#define EOF_MODE NETSHIM_EOF_SIGINT
#elif defined(TOOL_TRACEPATH)
#define PROG "tracepath"
#define EOF_MODE NETSHIM_EOF_SILENT
static const char *const table[][MAXARGS] = {
	{ "-n", "-m", "4", "127.0.0.1" },
	{ "-n", "-e", "-m", "4", "127.0.0.1" },
	{ "-6", "-n", "-m", "4", "::1" },
	{ "-6", "-n", "-e", "-m", "4", "::1" },
	{ "-b", "-m", "3", "-l", "1400", "127.0.0.1" },
	{ "-n", "-p", "4000", "-m", "6", "127.0.0.1" },
};
#elif defined(TOOL_CLOCKDIFF)
#define PROG "clockdiff"
#define EOF_MODE NETSHIM_EOF_SILENT
static const char *const table[][MAXARGS] = {
	{ "127.0.0.1" },
	{ "-o", "127.0.0.1" },
	{ "-1", "127.0.0.1" },
	{ "--time-format", "iso", "-o", "127.0.0.1" },
};
#elif defined(TOOL_ARPING)
#define PROG "arping"
#define EOF_MODE NETSHIM_EOF_SILENT
static const char *const table[][MAXARGS] = {
	{ "-c", "2", "-I", "eth0", "10.0.0.1" },
	{ "-D", "-c", "2", "-I", "eth0", "10.0.0.1" },
	{ "-b", "-c", "3", "-I", "eth0", "10.0.0.1" },
	{ "-A", "-c", "2", "-I", "eth0", "10.0.0.1" },
	{ "-f", "-c", "3", "-I", "eth0", "10.0.0.1" },
	{ "-s", "10.0.0.2", "-c", "2", "-I", "eth0", "10.0.0.1" },
	{ "-q", "-w", "3", "-I", "eth0", "10.0.0.1" },
	{ "-U", "-c", "2", "-I", "eth0", "10.0.0.1" },
};
#else
#error "build with -DTOOL_<NAME>"
#endif

static uint8_t *read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	uint8_t *buf = NULL;
	size_t cap = 0, n = 0, r;

	if (!f) {
		perror(path);
		exit(1);
	}
	do {
		if (n == cap) {
			cap = cap ? cap * 2 : 65536;
			buf = realloc(buf, cap);
			if (!buf)
				abort();
		}
		r = fread(buf + n, 1, cap - n, f);
		n += r;
	} while (r > 0);
	fclose(f);
	*len = n;
	return buf;
}

int main(int argc, char **argv)
{
	static char *args[MAXARGS + 4];
	uint8_t *data;
	size_t len, pos = 0;
	int n = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
		return 1;
	}
	data = read_file(argv[1], &len);
	args[n++] = PROG;

#if defined(TOOL_PING_ARGS)
	/* Arguments: NUL-terminated strings, an empty one ends the list. Copies keep each one
	 * NUL-terminated even when the file ends mid-argument. */
	while (n < 1 + 16 && pos < len) {
		size_t e = pos;
		while (e < len && data[e])
			e++;
		if (e == pos) {
			pos++;
			break;
		}
		args[n] = strndup((const char *)data + pos, e - pos);
		if (!args[n])
			abort();
		n++;
		pos = e < len ? e + 1 : e;
	}
	/* The destination is fixed: loopback of the family the arguments ask for. */
	{
		const char *dst = "127.0.0.1";
		for (int i = 1; i < n; i++)
			if (!strcmp(args[i], "-6"))
				dst = "::1";
		args[n++] = (char *)dst;
	}
#else
	if (len > 0) {
		const char *const *row = table[data[0] % (sizeof(table) / sizeof(table[0]))];
		for (int i = 0; i < MAXARGS && row[i]; i++)
			args[n++] = (char *)row[i];
		pos = 1;
	} else {
		const char *const *row = table[0];
		for (int i = 0; i < MAXARGS && row[i]; i++)
			args[n++] = (char *)row[i];
	}
#endif
	args[n] = NULL;
	netshim_init(data + pos, len - pos, EOF_MODE);
	return tool_main(n, args);
}
