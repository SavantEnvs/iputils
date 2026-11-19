/* mayhem/config.h: the config.h meson's configure_file() would generate for this build
 * (USE_CAP=false, USE_IDN=false, USE_GETTEXT=false) on Debian/glibc x86_64. The fuzz build
 * compiles the sources directly instead of through meson, which the base image lacks. */
#define PACKAGE_NAME "iputils"
#define HAVE___FPENDING 1
#define HAVE_GETRANDOM 1
#define HAVE_NANOSLEEP 1
#define HAVE_STRUCT_ICMP6_NODEINFO 1
#define TIME_WITH_SYS_TIME 1
#define HAVE_ERROR_H 1
