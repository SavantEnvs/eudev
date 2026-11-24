/* uevent / udev monitor messages: udev_monitor_receive_device() of the public libudev API
 * (libudev-monitor.c: the "libudev" header with its magic and properties_off bounds check, or the
 * kernel "ACTION@DEVPATH" header) and udev_device_new_from_nulstr() + the property parser of
 * libudev-device.c. The input is one datagram, sent over an AF_UNIX socketpair whose receiving end is
 * wrapped by udev_monitor_new_from_netlink_fd(). The kernel would give every netlink datagram a
 * netlink source address and root SCM_CREDENTIALS; the socketpair cannot, so recvmsg() is wrapped at
 * link time (-Wl,--wrap=recvmsg) to fill in exactly those two fields (multicast group 2, the udev
 * group, from uid 0) after the real recvmsg() has received the datagram. The resulting device is then
 * read back through the getters that do not touch sysfs. */
#include "fuzz_common.h"
#include <sys/socket.h>
#include <linux/netlink.h>
#include "libudev.h"
#include "libudev-private.h"

static int fuzz_rx = -1, fuzz_tx = -1;

ssize_t __real_recvmsg(int fd, struct msghdr *msg, int flags);
ssize_t __wrap_recvmsg(int fd, struct msghdr *msg, int flags) {
        /* the real call shrinks msg_namelen/msg_controllen to what the socketpair gave: keep the capacity */
        socklen_t namecap = msg->msg_namelen;
        size_t ctlcap = msg->msg_controllen;
        ssize_t n = __real_recvmsg(fd, msg, flags);
        if (n < 0 || fd != fuzz_rx)
                return n;
        if (msg->msg_name && namecap >= sizeof(struct sockaddr_nl)) {
                struct sockaddr_nl nl = { .nl_family = AF_NETLINK, .nl_pid = 0, .nl_groups = 2 };
                memcpy(msg->msg_name, &nl, sizeof nl);
                msg->msg_namelen = sizeof nl;
        }
        if (msg->msg_control && ctlcap >= CMSG_SPACE(sizeof(struct ucred))) {
                struct cmsghdr *c = (struct cmsghdr *) msg->msg_control;
                memset(c, 0, CMSG_SPACE(sizeof(struct ucred)));
                c->cmsg_len = CMSG_LEN(sizeof(struct ucred));
                c->cmsg_level = SOL_SOCKET;
                c->cmsg_type = SCM_CREDENTIALS;
                struct ucred cred = { .pid = 1, .uid = 0, .gid = 0 };
                memcpy(CMSG_DATA(c), &cred, sizeof cred);
                msg->msg_controllen = CMSG_SPACE(sizeof(struct ucred));
        }
        return n;
}

static volatile size_t sink;
static void use(const char *s) { if (s) sink += strlen(s); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        static struct udev *udev;
        static struct udev_monitor *mon;
        if (!udev) {
                int sv[2];
                setenv("SYSTEMD_LOG_LEVEL", "emerg", 1);
                setenv("UDEV_LOG", "emerg", 1);
                if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sv) < 0)
                        abort();
                int buf = 1 << 20;
                (void) setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);
                (void) setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
                fuzz_rx = sv[0];
                fuzz_tx = sv[1];
                udev = udev_new();
                if (!udev)
                        abort();
                mon = udev_monitor_new_from_netlink_fd(udev, "kernel", fuzz_rx);
                if (!mon)
                        abort();
        }
        if (size > 65536)
                return 0;
        /* drop anything a previous input left queued */
        char junk[1];
        while (recv(fuzz_rx, junk, sizeof junk, MSG_DONTWAIT | MSG_TRUNC) >= 0)
                ;
        if (send(fuzz_tx, data, size, 0) != (ssize_t) size)
                return 0;

        struct udev_device *dev = udev_monitor_receive_device(mon);
        if (!dev)
                return 0;
        use(udev_device_get_syspath(dev));
        use(udev_device_get_devpath(dev));
        use(udev_device_get_sysname(dev));
        use(udev_device_get_sysnum(dev));
        use(udev_device_get_subsystem(dev));
        use(udev_device_get_devtype(dev));
        use(udev_device_get_action(dev));
        use(udev_device_get_driver(dev));
        use(udev_device_get_devnode(dev));
        sink += udev_device_get_seqnum(dev) + udev_device_get_devnum(dev) +
                udev_device_get_usec_since_initialized(dev);
        struct udev_list_entry *e;
        udev_list_entry_foreach(e, udev_device_get_properties_list_entry(dev)) {
                use(udev_list_entry_get_name(e));
                use(udev_list_entry_get_value(e));
        }
        udev_list_entry_foreach(e, udev_device_get_devlinks_list_entry(dev))
                use(udev_list_entry_get_name(e));
        udev_list_entry_foreach(e, udev_device_get_tags_list_entry(dev))
                use(udev_list_entry_get_name(e));
        sink += udev_device_has_tag(dev, "systemd");
        use(udev_device_get_property_value(dev, "ID_MODEL"));
        udev_device_unref(dev);
        return 0;
}
