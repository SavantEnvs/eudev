/* udev rules file parser and checker: what `udevadm verify FILE` runs (udev_rules_check_file ->
 * udev_rules_parse_file_for_check in udev-rules.c, plus the checks of udev-rules-check.c). Names are
 * never resolved (resolve_names = -1, i.e. `--resolve-names=never`), so no NSS lookups happen. */
#include "fuzz_common.h"
#include "libudev.h"
#include "udev-rules-check.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        static char path[4200];
        static struct udev *udev;
        if (!udev) {
                udev = udev_new();
                if (!udev)
                        abort();
                snprintf(path, sizeof path, "%s/fuzz.rules", fuzz_scratch_dir());
        }
        fuzz_write_file(path, data, size);
        struct udev_rules_check *c = udev_rules_check_new(-1);
        if (!c)
                return 0;
        (void) udev_rules_check_file(udev, c, "fuzz.rules", path);
        (void) udev_rules_check_get_issues(c);
        udev_rules_check_free(c);
        return 0;
}
