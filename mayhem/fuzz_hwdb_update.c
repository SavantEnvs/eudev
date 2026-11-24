/* hwdb.d source compiler: what `udevadm hwdb --update --root=DIR` runs (hwdb_update() of hwdb-util.c:
 * the line parser, trie and string buffer, and the writer of hwdb.bin), followed by loading the written
 * hwdb.bin with the public udev_hwdb API and looking up the first match line of the input. The input is
 * one hwdb file, found through $UDEV_HWDB_PATH (relative to the root directory). */
#include "fuzz_common.h"
#include <sys/stat.h>
#include "libudev.h"
#include "hwdb-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        static char root[4200], src[4300], bin[4300];
        static struct udev *udev;
        if (!udev) {
                udev = udev_new();
                if (!udev)
                        abort();
                snprintf(root, sizeof root, "%s/root", fuzz_scratch_dir());
                snprintf(src, sizeof src, "%s/hwdb.d", root);
                snprintf(bin, sizeof bin, "%s/hwdb.bin", root);
                mkdir(root, 0700);
                mkdir(src, 0700);
                strcat(src, "/fuzz.hwdb");
                setenv("UDEV_HWDB_PATH", "/hwdb.d", 1);
                setenv("UDEV_HWDB_BIN", bin, 1);
        }
        unlink(bin);
        fuzz_write_file(src, data, size);
        if (hwdb_update(udev, root, "/hwdb.bin", false) < 0)
                return 0;

        /* the first line that is not a comment or a property: a match */
        char match[256] = "";
        const char *p = (const char *) data, *end = p + size;
        while (p < end) {
                const char *nl = memchr(p, '\n', (size_t) (end - p));
                size_t len = (size_t) ((nl ? nl : end) - p);
                if (len > 0 && p[0] != '#' && p[0] != ' ') {
                        if (len >= sizeof match)
                                len = sizeof match - 1;
                        memcpy(match, p, len);
                        match[len] = '\0';
                        break;
                }
                p = nl ? nl + 1 : end;
        }
        struct udev_hwdb *hwdb = udev_hwdb_new(udev);
        if (!hwdb)
                return 0;
        struct udev_list_entry *e;
        udev_list_entry_foreach(e, udev_hwdb_get_properties_list_entry(hwdb, match, 0))
                (void) udev_list_entry_get_value(e);
        udev_hwdb_unref(hwdb);
        return 0;
}
