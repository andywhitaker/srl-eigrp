#define _GNU_SOURCE
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define IPPROTO_EIGRPIGP 88

int srl_netns_restore_root(void) {
    int root_fd = open("/proc/1/ns/net", O_RDONLY | O_CLOEXEC);
    if (root_fd < 0) {
        root_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    }
    if (root_fd >= 0) {
        int ret = setns(root_fd, CLONE_NEWNET);
        close(root_fd);
        return ret;
    }
    return -1;
}

int srl_netns_enter(const char *netinst, int *saved_ns) {
    if (!saved_ns) return -1;
    *saved_ns = -1;

    char path[256];
    if (netinst && strcmp(netinst, "default") != 0 && strlen(netinst) > 0) {
        snprintf(path, sizeof(path), "/var/run/netns/srbase-%s", netinst);
    } else {
        snprintf(path, sizeof(path), "/var/run/netns/srbase-default");
    }

    int current_ns = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    if (current_ns < 0) {
        return -1;
    }

    int target_ns = open(path, O_RDONLY | O_CLOEXEC);
    if (target_ns < 0) {
        // Wait briefly if running in SR Linux and network-instance netns is being created
        if (access("/etc/opt/srlinux", F_OK) == 0) {
            for (int i = 0; i < 5; i++) {
                usleep(20000); // 20ms
                target_ns = open(path, O_RDONLY | O_CLOEXEC);
                if (target_ns >= 0) break;
            }
        }
    }
    if (target_ns < 0) {
        close(current_ns);
        return -1;
    }

    if (setns(target_ns, CLONE_NEWNET) < 0) {
        close(target_ns);
        close(current_ns);
        return -1;
    }

    close(target_ns);
    *saved_ns = current_ns;
    return 0;
}

void srl_netns_leave(int saved_ns) {
    if (saved_ns >= 0) {
        setns(saved_ns, CLONE_NEWNET);
        close(saved_ns);
    }
}

static void srl_set_socket_rcvbuf(int fd) {
    int bufsize = 8 * 1024 * 1024; // 8 MB ideal production buffer
#ifdef SO_RCVBUFFORCE
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &bufsize, sizeof(bufsize)) < 0) {
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    }
#else
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
#endif
}

int srl_netns_socket_open(const char *netinst) {
    int saved_ns = -1;
    if (srl_netns_enter(netinst, &saved_ns) < 0) {
        return -1;
    }

    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_EIGRPIGP);

    srl_netns_leave(saved_ns);

    if (fd < 0) return -1;

    srl_set_socket_rcvbuf(fd);

    int hincl = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

    int pktinfo = 1;
    setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &pktinfo, sizeof(pktinfo));

    uint8_t loop = 0;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));

    uint8_t ttl = 1;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

    int tos = 0xc0; // DSCP CS6 (Internetwork Control)
    setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

    return fd;
}

int srl_netns_ipv6_socket_open(const char *netinst) {
    int saved_ns = -1;
    if (srl_netns_enter(netinst, &saved_ns) < 0) {
        return -1;
    }

    int fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_EIGRPIGP);

    srl_netns_leave(saved_ns);

    if (fd < 0) return -1;

    srl_set_socket_rcvbuf(fd);

    int pktinfo = 1;
    setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &pktinfo, sizeof(pktinfo));

    int loop = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop));

    int hops = 1;
    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops));
    setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops));

    int tclass = 0xc0; // DSCP CS6 (Internetwork Control)
    setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tclass, sizeof(tclass));

    return fd;
}
