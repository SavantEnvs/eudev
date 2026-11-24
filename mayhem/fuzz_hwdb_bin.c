/* Compiled hwdb (hwdb.bin) reader of the public libudev API: udev_hwdb_new() opens and mmaps the file
 * named by $UDEV_HWDB_BIN and checks its header; udev_hwdb_get_properties_list_entry() walks the trie
 * (libudev-hwdb.c trie_search / fnmatch of the children). The input is the hwdb.bin; the lookups use
 * modaliases of the shipped hwdb.d plus one taken from the input's tail. */
#include "fuzz_common.h"
#include "libudev.h"

static const char *const modaliases[] = {
        "usb:v1D6Bp0001",
        "usb:v046Dp C52Bd1201dc00dsc00dp00ic03isc01ip02in00",
        "pci:v00008086d00001234sv00001028sd000004DE",
        "input:b0003v046Dp4024e0111-e0,1,2,3,4,k71,72,73,ram0,1,6,8,lsfw",
        "dmi:bvnLENOVO:bvrN2HET:svnLENOVO:pn20KF:pvrThinkPadX280:",
        "evdev:name:AT Translated Set 2 keyboard:phys:isa0060/serio0/input0:ev:120013:",
        "",
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        static char path[4200];
        static struct udev *udev;
        if (!udev) {
                udev = udev_new();
                if (!udev)
                        abort();
                snprintf(path, sizeof path, "%s/hwdb.bin", fuzz_scratch_dir());
                setenv("UDEV_HWDB_BIN", path, 1);
        }
        fuzz_write_file(path, data, size);
        struct udev_hwdb *hwdb = udev_hwdb_new(udev);
        if (!hwdb)
                return 0;
        char tail[65];
        size_t n = size < 64 ? size : 64;
        memcpy(tail, data + size - n, n);
        tail[n] = '\0';
        for (size_t i = 0; i <= sizeof modaliases / sizeof modaliases[0]; i++) {
                const char *m = i < sizeof modaliases / sizeof modaliases[0] ? modaliases[i] : tail;
                struct udev_list_entry *e;
                udev_list_entry_foreach(e, udev_hwdb_get_properties_list_entry(hwdb, m, 0)) {
                        const char *k = udev_list_entry_get_name(e);
                        const char *v = udev_list_entry_get_value(e);
                        if (k && v && k[0] == '\x01' && v[0] == '\x01')
                                __asm__ volatile("" ::: "memory");
                }
        }
        udev_hwdb_unref(hwdb);
        return 0;
}
