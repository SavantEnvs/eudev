/* Shared scratch-file helper for the eudev harnesses: each input is written to a file in a private
 * directory under $TMPDIR (the parsers under test read files by path), and rewritten for every input. */
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static const char *fuzz_scratch_dir(void) {
        static char dir[4096];
        if (dir[0] == '\0') {
                const char *t = getenv("TMPDIR");
                snprintf(dir, sizeof dir, "%s/eudev-fuzz-XXXXXX", (t && *t) ? t : "/tmp");
                if (!mkdtemp(dir))
                        abort();
        }
        return dir;
}

static int fuzz_write_file(const char *path, const uint8_t *data, size_t size) {
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0)
                abort();
        size_t off = 0;
        while (off < size) {
                ssize_t n = write(fd, data + off, size - off);
                if (n <= 0)
                        abort();
                off += (size_t) n;
        }
        close(fd);
        return 0;
}
