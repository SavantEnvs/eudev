/* scsi_id --config=FILE --whitelisted: the scsi_id.config parser of src/scsi_id/scsi_id.c
 * (get_file_options: OPTIONS= / VENDOR= / MODEL= lines, then the OPTIONS string split into an argv and
 * re-parsed by set_options). The tool is compiled into the harness unchanged, with its main() renamed;
 * it is called as `scsi_id --config=<input> --whitelisted` for every input. Its exit() calls (all in
 * set_options() and main(), both int-returning: --help/--version from the config's OPTIONS, and a bad
 * command line) become `return -1`, which main() already treats as a failure; its option globals and
 * glibc's getopt state are reset per input. */
#include "fuzz_common.h"

#define main scsi_id_main
#define exit(c) return -1
#include "../src/scsi_id/scsi_id.c"
#undef exit
#undef main

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        static char path[4200], arg[4300];
        if (!path[0]) {
                snprintf(path, sizeof path, "%s/scsi_id.config", fuzz_scratch_dir());
                snprintf(arg, sizeof arg, "--config=%s", path);
                setenv("SYSTEMD_LOG_LEVEL", "emerg", 1);
                setenv("UDEV_LOG", "emerg", 1);
        }
        fuzz_write_file(path, data, size);

        all_good = false;
        dev_specified = false;
        default_page_code = PAGE_UNSPECIFIED;
        sg_version = 4;
        reformat_serial = false;
        export = false;
        vendor_str[0] = model_str[0] = vendor_enc_str[0] = model_enc_str[0] = 0;
        revision_str[0] = type_str[0] = 0;
        optind = 0;

        char *argv[] = { (char *) "scsi_id", arg, (char *) "--whitelisted", NULL };
        (void) scsi_id_main(3, argv);
        fflush(stdout);

        /* set_options() sets optind = 1 (not 0) before getopt_long, so glibc does not reinitialise getopt
         * and would resume from its private __nextchar. An input that makes set_options() return in the
         * middle of a bundle of short options from the config's OPTIONS= (-h/-V, a bad -p/-s value) leaves
         * __nextchar pointing into the newargv that main() has since freed. Force a full getopt reset
         * (optind = 0 plus one call on an empty argv clears __nextchar) so the next input starts clean. */
        optind = 0;
        char *reset[] = { (char *) "x", NULL };
        (void) getopt_long(1, reset, "", NULL, NULL);
        return 0;
}
