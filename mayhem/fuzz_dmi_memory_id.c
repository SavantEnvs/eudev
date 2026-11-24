/* dmi_memory_id --from-dump=FILE: the SMBIOS/DMI entry point and table decoder of
 * src/dmi_memory_id/dmi_memory_id.c (type 16/17 structures, string table). The tool is compiled into
 * the harness unchanged; only its main() is not emitted, and its run() is called with
 * `dmi_memory_id -F <input>` for every input. Its one global, arg_source_file, is reset per input. */
#include "fuzz_common.h"
#include <getopt.h>
#include "main-func.h"
#undef DEFINE_MAIN_FUNCTION
#define DEFINE_MAIN_FUNCTION(impl) static int (*const dmi_run)(int, char *const *) = impl;
#include "../src/dmi_memory_id/dmi_memory_id.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        static char path[4200];
        if (!path[0]) {
                snprintf(path, sizeof path, "%s/dump.bin", fuzz_scratch_dir());
                setenv("SYSTEMD_LOG_LEVEL", "emerg", 1);
                setenv("UDEV_LOG", "emerg", 1);
        }
        fuzz_write_file(path, data, size);
        char *argv[] = { (char *) "dmi_memory_id", (char *) "-F", path, NULL };
        arg_source_file = NULL;
        optind = 0;
        (void) dmi_run(3, argv);
        fflush(stdout);
        return 0;
}
