#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <ctype.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "srl_cshim.h"
#include "eigrp_structs.h"
#include "eigrp_network.h"
#include "eigrp_interface.h"
#include "eigrp_metric.h"
#include "eigrp_redistribute.h"
#include "eigrp_neighbor.h"
#include "eigrp_packet.h"
#include "eigrp_prefix.h"
#include "eigrp_eventlog.h"
#include "eigrp_auth.h"
#include "eigrp_list.h"
#include "eigrp_table.h"
#include "eigrp_topology.h"

extern int srl_netns_socket_open(const char *netinst);
extern int srl_netns_enter(const char *netinst, int *saved_ns);
extern void srl_netns_leave(int saved_ns);

/* ------------------------------------------------------------------------
 * Event and Timer Runtime
 * ------------------------------------------------------------------------ */

typedef enum srl_event_kind {
    SRL_EVENT_IMMEDIATE = 0,
    SRL_EVENT_TIMER,
    SRL_EVENT_READ,
    SRL_EVENT_WRITE,
} srl_event_kind_t;

struct eigrp_event {
    srl_event_kind_t kind;
    eigrp_event_callback_t callback;
    void *arg;
    eigrp_event_t **owner;
    uint64_t due_msec;
    int fd;
    struct eigrp_event *next;
};

typedef struct srl_runtime {
    pthread_mutex_t lock;
    pthread_t thread;
    bool initialized;
    bool running;
    int wake_read;
    int wake_write;
    eigrp_event_t *events;
} srl_runtime_t;

static srl_runtime_t g_runtime = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .wake_read = -1,
    .wake_write = -1,
};

static uint64_t srl_monotime_msec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000U) + ((uint64_t)ts.tv_nsec / 1000000U);
}

static void srl_runtime_wake(void) {
    char b = 'w';
    if (g_runtime.wake_write >= 0) {
        ssize_t n = write(g_runtime.wake_write, &b, sizeof(b));
        (void)n;
    }
}

static void srl_runtime_wake_drain(void) {
    char buf[64];
    while (read(g_runtime.wake_read, buf, sizeof(buf)) > 0) {}
}

static bool srl_event_unlink(eigrp_event_t *event) {
    eigrp_event_t **curr = &g_runtime.events;
    while (*curr) {
        if (*curr == event) {
            *curr = event->next;
            return true;
        }
        curr = &(*curr)->next;
    }
    return false;
}

void eigrp_sys_event_cancel(eigrp_event_t **owner) {
    if (!owner || !*owner) return;
    eigrp_event_t *ev = NULL;
    pthread_mutex_lock(&g_runtime.lock);
    ev = *owner;
    if (ev) {
        *owner = NULL;
        srl_event_unlink(ev);
    }
    pthread_mutex_unlock(&g_runtime.lock);
    if (ev) {
        free(ev);
        srl_runtime_wake();
    }
}

static eigrp_event_t *srl_event_prepare(eigrp_event_t **owner, srl_event_kind_t kind,
                                       eigrp_event_callback_t cb, void *arg,
                                       uint32_t delay_msec, int fd) {
    if (!owner || !cb) return NULL;
    eigrp_sys_event_cancel(owner);

    eigrp_event_t *ev = calloc(1, sizeof(*ev));
    if (!ev) return NULL;
    ev->kind = kind;
    ev->callback = cb;
    ev->arg = arg;
    ev->owner = owner;
    ev->due_msec = srl_monotime_msec() + delay_msec;
    ev->fd = fd;

    pthread_mutex_lock(&g_runtime.lock);
    if (!g_runtime.running) {
        pthread_mutex_unlock(&g_runtime.lock);
        free(ev);
        return NULL;
    }
    ev->next = g_runtime.events;
    g_runtime.events = ev;
    *owner = ev;
    pthread_mutex_unlock(&g_runtime.lock);
    srl_runtime_wake();
    return ev;
}

void eigrp_sys_event_add(eigrp_event_t **event, eigrp_event_callback_t cb, void *arg) {
    (void)srl_event_prepare(event, SRL_EVENT_IMMEDIATE, cb, arg, 0, -1);
}

void eigrp_sys_timer_add(eigrp_event_t **event, eigrp_event_callback_t cb, void *arg, uint32_t delay) {
    (void)srl_event_prepare(event, SRL_EVENT_TIMER, cb, arg, delay, -1);
}

uint32_t eigrp_sys_timer_remaining_seconds(const eigrp_event_t *event) {
    if (!event || event->kind != SRL_EVENT_TIMER) return 0;
    uint64_t now = srl_monotime_msec();
    if (event->due_msec <= now) return 0;
    return (uint32_t)((event->due_msec - now + 999U) / 1000U);
}

/* ------------------------------------------------------------------------
 * Instances, Bindings & Interface Tables
 * ------------------------------------------------------------------------ */

typedef struct srl_binding {
    eigrp_instance_t *eigrp;
    char netinst[64];
    uint32_t vrf_id;
    int fd;      /* raw IP proto-88 socket in srbase-<netinst>: TX + multicast RX */
    int pkt_fd;  /* AF_PACKET socket on wire ports: unicast RX fallback (-1 if off) */
    int rx_fd;   /* fd the event loop polls: epoll over fd+pkt_fd, or fd itself */
    struct srl_binding *next;
} srl_binding_t;

typedef struct srl_vrf_entry {
    char netinst[64];
    uint32_t vrf_id;
    struct srl_vrf_entry *next;
} srl_vrf_entry_t;

static srl_vrf_entry_t *g_vrf_entries = NULL;
static uint32_t g_next_vrf_id = 1;

typedef struct srl_intf {
    char netinst[64];
    char ifname[64];
    eigrp_ifindex_t ifindex;
    eigrp_prefix_t address;
    eigrp_prefix_t address_v6;
    eigrp_prefix_t global_v6;
    uint32_t bandwidth;
    uint32_t mtu;
    bool active;
    bool active_v6;
    bool passive;
    bool passive_v6;
    char auth_mode[32];
    char keychain[64];
    char auth_key[256];
    char auth_mode_v4[32];
    char keychain_v4[64];
    char auth_key_v4[256];
    char auth_mode_v6[32];
    char keychain_v6[64];
    char auth_key_v6[256];
    struct srl_intf *next;
} srl_intf_t;

static bool srl_match_ifname(const char *dev_name, const char *cfg_name) {
    if (!dev_name || !cfg_name) return false;
    if (strcmp(dev_name, cfg_name) == 0) return true;

    int ds_inst = 0, ds_sub = 0;
    int cs_inst = 0, cs_sub = 0;
    bool dev_sys = false, cfg_sys = false;

    if (sscanf(dev_name, "system%d.%d", &ds_inst, &ds_sub) == 2) {
        dev_sys = true;
    } else if (sscanf(dev_name, "system%d", &ds_inst) == 1) {
        ds_sub = 0;
        dev_sys = true;
    }

    if (sscanf(cfg_name, "system%d.%d", &cs_inst, &cs_sub) == 2) {
        cfg_sys = true;
    } else if (sscanf(cfg_name, "system%d", &cs_inst) == 1) {
        cs_sub = 0;
        cfg_sys = true;
    }

    if (dev_sys && cfg_sys) {
        return (ds_inst == cs_inst && ds_sub == cs_sub);
    }

    int dc1 = 0, dp1 = 0, ds1 = 0;
    int cc1 = 0, cp1 = 0, cs1 = 0;
    bool dev_parsed = false;
    if (sscanf(dev_name, "e%d-%d.%d", &dc1, &dp1, &ds1) == 3) {
        dev_parsed = true;
    } else if (sscanf(dev_name, "ethernet-%d/%d.%d", &dc1, &dp1, &ds1) == 3) {
        dev_parsed = true;
    } else if (sscanf(dev_name, "e%d-%d", &dc1, &dp1) == 2) {
        ds1 = 0;
        dev_parsed = true;
    } else if (sscanf(dev_name, "ethernet-%d/%d", &dc1, &dp1) == 2) {
        ds1 = 0;
        dev_parsed = true;
    }

    bool cfg_parsed = false;
    if (sscanf(cfg_name, "ethernet-%d/%d.%d", &cc1, &cp1, &cs1) == 3) {
        cfg_parsed = true;
    } else if (sscanf(cfg_name, "e%d-%d.%d", &cc1, &cp1, &cs1) == 3) {
        cfg_parsed = true;
    } else if (sscanf(cfg_name, "ethernet-%d/%d", &cc1, &cp1) == 2) {
        cs1 = 0;
        cfg_parsed = true;
    } else if (sscanf(cfg_name, "e%d-%d", &cc1, &cp1) == 2) {
        cs1 = 0;
        cfg_parsed = true;
    }

    if (dev_parsed && cfg_parsed) {
        return (dc1 == cc1 && dp1 == cp1 && ds1 == cs1);
    }
    return false;
}

static eigrp_ifindex_t srl_resolve_ifindex_dev(const char *ifname, char *dev_name_out, size_t dev_len) {
    if (!ifname || !ifname[0]) return 0;
    if (dev_name_out && dev_len > 0) dev_name_out[0] = '\0';

    eigrp_ifindex_t idx = (eigrp_ifindex_t)if_nametoindex(ifname);
    if (idx > 0) {
        if (dev_name_out && dev_len > 0) {
            strncpy(dev_name_out, ifname, dev_len - 1);
            dev_name_out[dev_len - 1] = '\0';
        }
        return idx;
    }

    struct if_nameindex *nlist = if_nameindex();
    if (nlist) {
        for (struct if_nameindex *cur = nlist; cur->if_index != 0 && cur->if_name != NULL; cur++) {
            if (srl_match_ifname(cur->if_name, ifname)) {
                idx = (eigrp_ifindex_t)cur->if_index;
                if (dev_name_out && dev_len > 0) {
                    strncpy(dev_name_out, cur->if_name, dev_len - 1);
                    dev_name_out[dev_len - 1] = '\0';
                }
                break;
            }
        }
        if_freenameindex(nlist);
    }
    return idx;
}

static srl_binding_t *g_bindings = NULL;
static srl_intf_t *g_interfaces = NULL;
static pthread_mutex_t g_data_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static char g_pending_netinst[64] = "default";

static uint32_t srl_vrf_id_get(const char *netinst) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    if (strcmp(ni, "default") == 0) {
        return EIGRP_VRF_DEFAULT; // 0
    }
    pthread_mutex_lock(&g_data_lock);
    for (srl_vrf_entry_t *v = g_vrf_entries; v; v = v->next) {
        if (strcmp(v->netinst, ni) == 0) {
            uint32_t id = v->vrf_id;
            pthread_mutex_unlock(&g_data_lock);
            return id;
        }
    }
    srl_vrf_entry_t *v = calloc(1, sizeof(*v));
    if (v) {
        strncpy(v->netinst, ni, sizeof(v->netinst) - 1);
        v->vrf_id = g_next_vrf_id++;
        v->next = g_vrf_entries;
        g_vrf_entries = v;
        uint32_t id = v->vrf_id;
        pthread_mutex_unlock(&g_data_lock);
        return id;
    }
    pthread_mutex_unlock(&g_data_lock);
    return EIGRP_VRF_DEFAULT;
}

static const char *srl_netinst_by_vrf(uint32_t vrf_id) {
    if (vrf_id == EIGRP_VRF_DEFAULT) return "default";
    pthread_mutex_lock(&g_data_lock);
    for (srl_vrf_entry_t *v = g_vrf_entries; v; v = v->next) {
        if (v->vrf_id == vrf_id) {
            pthread_mutex_unlock(&g_data_lock);
            return v->netinst;
        }
    }
    pthread_mutex_unlock(&g_data_lock);
    return "default";
}

const char *srl_netinst_by_instance(eigrp_instance_t *e) {
    if (!e) return "default";
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b; b = b->next) {
        if (b->eigrp == e) {
            pthread_mutex_unlock(&g_data_lock);
            return b->netinst;
        }
    }
    pthread_mutex_unlock(&g_data_lock);
    return srl_netinst_by_vrf(e->vrf_id);
}

static eigrp_instance_t *srl_instance_get_afi(const char *netinst, eigrp_afi_t afi) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b; b = b->next) {
        if (strcmp(b->netinst, ni) == 0 && b->eigrp && eigrp_instance_afi(b->eigrp) == afi) {
            eigrp_instance_t *e = b->eigrp;
            pthread_mutex_unlock(&g_data_lock);
            return e;
        }
    }
    pthread_mutex_unlock(&g_data_lock);
    return NULL;
}

static eigrp_instance_t *srl_instance_get(const char *netinst) {
    eigrp_instance_t *e = srl_instance_get_afi(netinst, EIGRP_AFI_IPV4);
    if (!e) {
        e = srl_instance_get_afi(netinst, EIGRP_AFI_IPV6);
    }
    return e;
}

static int srl_socket_fd_get(eigrp_instance_t *eigrp) {
    pthread_mutex_lock(&g_data_lock);
    srl_binding_t *b = g_bindings;
    while (b) {
        if (b->eigrp == eigrp) {
            int fd = b->fd;
            pthread_mutex_unlock(&g_data_lock);
            return fd;
        }
        b = b->next;
    }
    pthread_mutex_unlock(&g_data_lock);
    return -1;
}

static srl_binding_t *srl_binding_get(eigrp_instance_t *eigrp) {
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b; b = b->next) {
        if (b->eigrp == eigrp) {
            pthread_mutex_unlock(&g_data_lock);
            return b;
        }
    }
    pthread_mutex_unlock(&g_data_lock);
    return NULL;
}

static int srl_socket_rxfd_get(eigrp_instance_t *eigrp) {
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b; b = b->next) {
        if (b->eigrp == eigrp) {
            int fd = (b->rx_fd >= 0) ? b->rx_fd : b->fd;
            pthread_mutex_unlock(&g_data_lock);
            return fd;
        }
    }
    pthread_mutex_unlock(&g_data_lock);
    return -1;
}

void eigrp_sys_read_add(eigrp_event_t **event, eigrp_instance_t *e, eigrp_event_callback_t cb, void *arg) {
    int fd = srl_socket_rxfd_get(e);
    if (fd < 0) return;
    (void)srl_event_prepare(event, SRL_EVENT_READ, cb, arg, 0, fd);
}


void eigrp_sys_write_add(eigrp_event_t **event, eigrp_instance_t *e, eigrp_event_callback_t cb, void *arg) {
    int fd = srl_socket_fd_get(e);
    if (fd < 0) return;
    (void)srl_event_prepare(event, SRL_EVENT_WRITE, cb, arg, 0, fd);
}

static int srl_poll_timeout_locked(uint64_t now) {
    eigrp_event_t *ev;
    uint64_t nearest = UINT64_MAX;

    for (ev = g_runtime.events; ev; ev = ev->next) {
        if (ev->kind == SRL_EVENT_IMMEDIATE) {
            return 0;
        }
        if (ev->kind == SRL_EVENT_TIMER && ev->due_msec < nearest) {
            nearest = ev->due_msec;
        }
    }
    if (nearest == UINT64_MAX) return 1000; // poll at least every 1s
    if (nearest <= now) return 0;
    if (nearest - now > (uint64_t)INT_MAX) return INT_MAX;
    return (int)(nearest - now);
}

static size_t srl_pollfds_build_locked(struct pollfd **pollfds, eigrp_event_t ***events) {
    size_t count = 1; // wake_read
    eigrp_event_t *ev;
    for (ev = g_runtime.events; ev; ev = ev->next) {
        if (ev->kind == SRL_EVENT_READ || ev->kind == SRL_EVENT_WRITE) {
            count++;
        }
    }

    struct pollfd *pfds = calloc(count, sizeof(*pfds));
    eigrp_event_t **ev_map = calloc(count, sizeof(*ev_map));
    if (!pfds || !ev_map) {
        free(pfds);
        free(ev_map);
        *pollfds = NULL;
        *events = NULL;
        return 0;
    }

    pfds[0].fd = g_runtime.wake_read;
    pfds[0].events = POLLIN;

    size_t idx = 1;
    for (ev = g_runtime.events; ev; ev = ev->next) {
        if (ev->kind != SRL_EVENT_READ && ev->kind != SRL_EVENT_WRITE) continue;
        pfds[idx].fd = ev->fd;
        pfds[idx].events = (ev->kind == SRL_EVENT_READ) ? POLLIN : POLLOUT;
        ev_map[idx] = ev;
        idx++;
    }

    *pollfds = pfds;
    *events = ev_map;
    return count;
}

static eigrp_event_t *srl_ready_take_locked(struct pollfd *pollfds, eigrp_event_t **ev_map, size_t count, uint64_t now) {
    eigrp_event_t *ev;
    for (ev = g_runtime.events; ev; ev = ev->next) {
        if (ev->kind == SRL_EVENT_IMMEDIATE ||
            (ev->kind == SRL_EVENT_TIMER && ev->due_msec <= now)) {
            if (srl_event_unlink(ev)) return ev;
        }
    }
    for (size_t i = 1; i < count; i++) {
        if (!ev_map[i] || !pollfds[i].revents) continue;
        ev = ev_map[i];
        ev_map[i] = NULL;
        pollfds[i].revents = 0;
        if (srl_event_unlink(ev)) return ev;
    }
    return NULL;
}

static void *srl_runtime_loop(void *arg) {
    (void)arg;
    while (1) {
        struct pollfd *pfds = NULL;
        eigrp_event_t **ev_map = NULL;
        int timeout;
        size_t count;

        pthread_mutex_lock(&g_runtime.lock);
        if (!g_runtime.running) {
            pthread_mutex_unlock(&g_runtime.lock);
            break;
        }
        uint64_t now = srl_monotime_msec();
        timeout = srl_poll_timeout_locked(now);
        count = srl_pollfds_build_locked(&pfds, &ev_map);
        pthread_mutex_unlock(&g_runtime.lock);

        if (count == 0) {
            usleep(10000);
            continue;
        }

        int ret = poll(pfds, count, timeout);
        (void)ret;

        if (pfds[0].revents & POLLIN) {
            srl_runtime_wake_drain();
        }

        while (1) {
            pthread_mutex_lock(&g_runtime.lock);
            eigrp_event_t *ready = srl_ready_take_locked(pfds, ev_map, count, srl_monotime_msec());
            if (ready && ready->owner && *ready->owner == ready) {
                *ready->owner = NULL;
            }
            pthread_mutex_unlock(&g_runtime.lock);

            if (!ready) break;

            eigrp_event_callback_t cb = ready->callback;
            void *cb_arg = ready->arg;
            free(ready);
            if (cb) {
                cb(cb_arg);
            }
        }

        free(ev_map);
        free(pfds);
    }
    return NULL;
}

void eigrp_sys_runtime_init(void) {
    pthread_mutex_lock(&g_runtime.lock);
    if (g_runtime.initialized) {
        pthread_mutex_unlock(&g_runtime.lock);
        return;
    }
    int p[2];
    if (pipe(p) != 0) {
        pthread_mutex_unlock(&g_runtime.lock);
        return;
    }
    g_runtime.wake_read = p[0];
    g_runtime.wake_write = p[1];
    (void)fcntl(g_runtime.wake_read, F_SETFL, fcntl(g_runtime.wake_read, F_GETFL, 0) | O_NONBLOCK);
    (void)fcntl(g_runtime.wake_write, F_SETFL, fcntl(g_runtime.wake_write, F_GETFL, 0) | O_NONBLOCK);
    g_runtime.running = true;
    g_runtime.initialized = true;
    pthread_mutex_unlock(&g_runtime.lock);

    pthread_create(&g_runtime.thread, NULL, srl_runtime_loop, NULL);
}

void eigrp_sys_runtime_finish(void) {
    pthread_mutex_lock(&g_runtime.lock);
    if (!g_runtime.initialized) {
        pthread_mutex_unlock(&g_runtime.lock);
        return;
    }
    g_runtime.running = false;
    pthread_mutex_unlock(&g_runtime.lock);

    srl_runtime_wake();
    pthread_join(g_runtime.thread, NULL);

    pthread_mutex_lock(&g_runtime.lock);
    eigrp_event_t *ev;
    while ((ev = g_runtime.events) != NULL) {
        g_runtime.events = ev->next;
        if (ev->owner && *ev->owner == ev) *ev->owner = NULL;
        free(ev);
    }
    close(g_runtime.wake_read);
    close(g_runtime.wake_write);
    g_runtime.wake_read = -1;
    g_runtime.wake_write = -1;
    g_runtime.initialized = false;
    pthread_mutex_unlock(&g_runtime.lock);
}

uint64_t eigrp_sys_monotime_msec(void) {
    return srl_monotime_msec();
}

uint64_t eigrp_sys_wallclock_msec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec * 1000U) + ((uint64_t)ts.tv_nsec / 1000000U);
}

void eigrp_sys_software_version(uint8_t *major, uint8_t *minor) {
    if (major) *major = 1;
    if (minor) *minor = 0;
}

/* ------------------------------------------------------------------------
 * Work Queue Services
 * ------------------------------------------------------------------------ */

typedef struct srl_work_item {
    void *data;
    struct srl_work_item *next;
} srl_work_item_t;

struct eigrp_work_queue {
    eigrp_instance_t *eigrp;
    char *name;
    eigrp_work_queue_func_t workfunc;
    eigrp_work_queue_delete_func_t deletefunc;
    srl_work_item_t *head;
    srl_work_item_t *tail;
    eigrp_event_t *event;
    bool blocked;
};

static void srl_work_queue_run(void *arg) {
    eigrp_work_queue_t *q = arg;
    if (!q || !q->workfunc) return;
    srl_work_item_t *item = q->head;
    if (!item) return;

    eigrp_work_queue_result_t res = q->workfunc(q, item->data);
    if (res == EIGRP_WORK_QUEUE_BLOCKED) {
        q->blocked = true;
        return;
    }
    if (res == EIGRP_WORK_QUEUE_REQUEUE) {
        item = q->head;
        q->head = item->next;
        if (!q->head) q->tail = NULL;
        item->next = NULL;
        if (q->tail) q->tail->next = item;
        else q->head = item;
        q->tail = item;
    } else {
        q->head = item->next;
        if (!q->head) q->tail = NULL;
        free(item);
    }
    if (q->head) {
        eigrp_sys_event_add(&q->event, srl_work_queue_run, q);
    }
}

eigrp_work_queue_t *eigrp_sys_work_queue_create(eigrp_instance_t *e, const char *n,
                                              eigrp_work_queue_func_t w,
                                              eigrp_work_queue_delete_func_t d) {
    if (!e || !n || !w) return NULL;
    eigrp_work_queue_t *q = calloc(1, sizeof(*q));
    if (!q) return NULL;
    q->eigrp = e;
    q->name = strdup(n);
    q->workfunc = w;
    q->deletefunc = d;
    return q;
}

void eigrp_sys_work_queue_free(eigrp_work_queue_t *q) {
    if (!q) return;
    eigrp_sys_work_queue_clear(q);
    free(q->name);
    free(q);
}

void eigrp_sys_work_queue_clear(eigrp_work_queue_t *q) {
    if (!q) return;
    eigrp_sys_event_cancel(&q->event);
    srl_work_item_t *item;
    while ((item = q->head) != NULL) {
        q->head = item->next;
        if (q->deletefunc) q->deletefunc(q, item->data);
        free(item);
    }
    q->tail = NULL;
    q->blocked = false;
}

void eigrp_sys_work_queue_enqueue(eigrp_work_queue_t *q, void *data) {
    if (!q || !data) return;
    srl_work_item_t *item = calloc(1, sizeof(*item));
    if (!item) return;
    item->data = data;
    if (q->tail) q->tail->next = item;
    else q->head = item;
    q->tail = item;
    q->blocked = false;
    if (!q->event) {
        eigrp_sys_event_add(&q->event, srl_work_queue_run, q);
    }
}

eigrp_instance_t *eigrp_sys_work_queue_instance(eigrp_work_queue_t *q) {
    return q ? q->eigrp : NULL;
}

/* ------------------------------------------------------------------------
 * Sockets & Multicast
 * ------------------------------------------------------------------------ */

eigrp_result_t eigrp_sys_socket_open(eigrp_instance_t *eigrp) {
    if (!eigrp) return EIGRP_RESULT_INVALID_ARGUMENT;

    const char *netinst = srl_netinst_by_vrf(eigrp->vrf_id);
    pthread_mutex_lock(&g_data_lock);
    if (g_pending_netinst[0]) {
        netinst = g_pending_netinst;
    }
    pthread_mutex_unlock(&g_data_lock);

    bool is_v6 = (eigrp_instance_afi(eigrp) == EIGRP_AFI_IPV6);
    int fd = is_v6 ? srl_netns_ipv6_socket_open(netinst) : srl_netns_socket_open(netinst);
    if (fd < 0) {
        return EIGRP_RESULT_INTERNAL_FAILURE;
    }

    srl_binding_t *b = calloc(1, sizeof(*b));
    if (!b) {
        close(fd);
        return EIGRP_RESULT_INTERNAL_FAILURE;
    }
    b->eigrp = eigrp;
    b->vrf_id = eigrp->vrf_id;
    snprintf(b->netinst, sizeof(b->netinst), "%s", netinst);
    b->fd = fd;
    b->pkt_fd = -1;
    b->rx_fd = -1;

    // AF_PACKET raw socket in root namespace to capture unicast proto-88 packets
    // that are discarded by SR Linux dataplane (sr_xdp_lc).
    // Using ETH_P_ALL allows capturing both untagged frames and 802.1Q tagged frames.
    srl_netns_restore_root();
    b->pkt_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (b->pkt_fd >= 0) {
        fcntl(b->pkt_fd, F_SETFL, fcntl(b->pkt_fd, F_GETFL, 0) | O_NONBLOCK);
        struct packet_mreq mr;
        memset(&mr, 0, sizeof(mr));
        mr.mr_type = PACKET_MR_PROMISC;
        setsockopt(b->pkt_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
    }

    // Epoll fd to monitor both fd and pkt_fd
    b->rx_fd = epoll_create1(EPOLL_CLOEXEC);
    if (b->rx_fd >= 0) {
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        ev.data.fd = b->fd;
        epoll_ctl(b->rx_fd, EPOLL_CTL_ADD, b->fd, &ev);

        if (b->pkt_fd >= 0) {
            memset(&ev, 0, sizeof(ev));
            ev.events = EPOLLIN;
            ev.data.fd = b->pkt_fd;
            epoll_ctl(b->rx_fd, EPOLL_CTL_ADD, b->pkt_fd, &ev);
        }
    } else {
        b->rx_fd = b->fd;
    }

    pthread_mutex_lock(&g_data_lock);
    b->next = g_bindings;
    g_bindings = b;
    pthread_mutex_unlock(&g_data_lock);

    srl_runtime_wake();
    return EIGRP_RESULT_SUCCESS;
}

void eigrp_sys_socket_close(eigrp_instance_t *eigrp) {
    pthread_mutex_lock(&g_data_lock);
    srl_binding_t **curr = &g_bindings;
    srl_binding_t *del = NULL;
    while (*curr) {
        if ((*curr)->eigrp == eigrp) {
            del = *curr;
            *curr = del->next;
            break;
        }
        curr = &(*curr)->next;
    }
    pthread_mutex_unlock(&g_data_lock);

    if (del) {
        pthread_mutex_lock(&g_runtime.lock);
        eigrp_event_t **ev_curr = &g_runtime.events;
        while (*ev_curr) {
            eigrp_event_t *ev = *ev_curr;
            if ((ev->kind == SRL_EVENT_READ || ev->kind == SRL_EVENT_WRITE) &&
                (ev->fd == del->fd || ev->fd == del->rx_fd || ev->fd == del->pkt_fd)) {
                *ev_curr = ev->next;
                if (ev->owner && *ev->owner == ev) *ev->owner = NULL;
                free(ev);
            } else {
                ev_curr = &(*ev_curr)->next;
            }
        }
        pthread_mutex_unlock(&g_runtime.lock);

        if (del->rx_fd >= 0 && del->rx_fd != del->fd) {
            close(del->rx_fd);
        }
        if (del->pkt_fd >= 0) {
            close(del->pkt_fd);
        }
        if (del->fd >= 0) {
            close(del->fd);
        }
        free(del);
        srl_runtime_wake();
    }
}

void eigrp_sys_socket_send_buffer_ensure(eigrp_instance_t *e, uint32_t min_bytes) {
    int fd = srl_socket_fd_get(e);
    if (fd >= 0 && min_bytes > 0) {
        int val = (int)min_bytes;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
    }
}

bool eigrp_sys_router_id_get(eigrp_instance_t *e, uint32_t *rid) {
    (void)e;
    (void)rid;
    return false;
}

eigrp_result_t eigrp_sys_vrf_resolve(const char *name, eigrp_vrf_id_t *vid) {
    if (vid) *vid = (eigrp_vrf_id_t)srl_vrf_id_get(name);
    return EIGRP_RESULT_SUCCESS;
}

int eigrp_sys_multicast_interface_update(eigrp_operation_t op, eigrp_instance_t *e, eigrp_intf_t *ei) {
    if (op != EIGRP_SET || !e || !ei) return 0;
    int fd = srl_socket_fd_get(e);
    if (fd < 0) return -1;

    if (eigrp_instance_afi(e) == EIGRP_AFI_IPV6) {
        int idx = (int)eigrp_intf_ifindex(ei);
        return setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &idx, sizeof(idx));
    }

    struct ip_mreqn mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_ifindex = (int)eigrp_intf_ifindex(ei);

    eigrp_prefix_t local_addr;
    if (eigrp_intf_address_read(ei, &local_addr) == EIGRP_RESULT_SUCCESS) {
        memcpy(&mreq.imr_address, local_addr.address.bytes, sizeof(struct in_addr));
    }
    return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreq, sizeof(mreq));
}

int eigrp_sys_multicast_join(eigrp_instance_t *e, eigrp_intf_t *ei) {
    if (!e || !ei) return -1;
    int fd = srl_socket_fd_get(e);
    if (fd < 0) return -1;

    if (eigrp_instance_afi(e) == EIGRP_AFI_IPV6) {
        struct ipv6_mreq mreq6;
        memset(&mreq6, 0, sizeof(mreq6));
        inet_pton(AF_INET6, "ff02::a", &mreq6.ipv6mr_multiaddr);
        mreq6.ipv6mr_interface = (int)eigrp_intf_ifindex(ei);
        return setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6));
    }

    struct ip_mreqn mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = htonl(EIGRP_MULTICAST_ADDRESS);
    mreq.imr_ifindex = (int)eigrp_intf_ifindex(ei);

    return setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
}

int eigrp_sys_multicast_leave(eigrp_instance_t *e, eigrp_intf_t *ei) {
    if (!e || !ei) return -1;
    int fd = srl_socket_fd_get(e);
    if (fd < 0) return -1;

    if (eigrp_instance_afi(e) == EIGRP_AFI_IPV6) {
        struct ipv6_mreq mreq6;
        memset(&mreq6, 0, sizeof(mreq6));
        inet_pton(AF_INET6, "ff02::a", &mreq6.ipv6mr_multiaddr);
        mreq6.ipv6mr_interface = (int)eigrp_intf_ifindex(ei);
        return setsockopt(fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq6, sizeof(mreq6));
    }

    struct ip_mreqn mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = htonl(EIGRP_MULTICAST_ADDRESS);
    mreq.imr_ifindex = (int)eigrp_intf_ifindex(ei);

    return setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
}

/* ------------------------------------------------------------------------
 * Packet Send & Receive
 * ------------------------------------------------------------------------ */

static uint16_t srl_ip_checksum(const void *buf, size_t hdr_len) {
    const uint16_t *words = (const uint16_t *)buf;
    uint32_t sum = 0;
    while (hdr_len > 1) {
        sum += *words++;
        hdr_len -= 2;
    }
    if (hdr_len > 0) {
        sum += *(const uint8_t *)words;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

int eigrp_sys_ipv4_packet_send(eigrp_instance_t *eigrp, eigrp_intf_t *ei,
                               const eigrp_address_t *dst, const uint8_t *payload, size_t length) {
    int fd = srl_socket_fd_get(eigrp);
    if (fd < 0 || !ei || !dst || !payload) return -1;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    memcpy(&sin.sin_addr, dst->bytes, sizeof(sin.sin_addr));

    eigrp_prefix_t local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    eigrp_intf_address_read(ei, &local_addr);

    // If destination is multicast, set outgoing multicast interface
    if (sin.sin_addr.s_addr == htonl(EIGRP_MULTICAST_ADDRESS)) {
        eigrp_sys_multicast_interface_update(EIGRP_SET, eigrp, ei);
    }

    struct ip iph;
    memset(&iph, 0, sizeof(iph));
    iph.ip_hl = 5;
    iph.ip_v = 4;
    iph.ip_tos = 0xC0; // Internetwork Control
    iph.ip_len = htons((uint16_t)(sizeof(struct ip) + length));
    iph.ip_ttl = 64;
    iph.ip_p = 88;
    iph.ip_dst = sin.sin_addr;
    memcpy(&iph.ip_src, local_addr.address.bytes, sizeof(iph.ip_src));
    iph.ip_sum = 0;
    iph.ip_sum = srl_ip_checksum(&iph, sizeof(iph));

    struct iovec iov[2];
    iov[0].iov_base = &iph;
    iov[0].iov_len = sizeof(iph);
    iov[1].iov_base = (void *)payload;
    iov[1].iov_len = length;

    char cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
    memset(cbuf, 0, sizeof(cbuf));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sin;
    msg.msg_namelen = sizeof(sin);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
    pktinfo->ipi_ifindex = (int)eigrp_intf_ifindex(ei);
    memcpy(&pktinfo->ipi_spec_dst, local_addr.address.bytes, sizeof(pktinfo->ipi_spec_dst));

    int flags = 0;
    if (!IN_MULTICAST(ntohl(sin.sin_addr.s_addr))) {
        flags = MSG_DONTROUTE;
    }

    ssize_t ret = sendmsg(fd, &msg, flags);
    if (ret < 0) {
        fprintf(stderr, "CSHIM TX ERR: sendmsg fd=%d ifindex=%u dst=%s len=%zu errno=%d (%s)\n",
                fd, (unsigned)eigrp_intf_ifindex(ei),
                inet_ntoa(sin.sin_addr), length, errno, strerror(errno));
    }
    return (int)ret;
}

bool eigrp_sys_ipv4_packet_receive(eigrp_instance_t *eigrp, uint8_t *buffer, size_t capacity,
                                   size_t *rx_len, eigrp_ifindex_t *ifindex, eigrp_address_t *src,
                                   eigrp_address_t *dst, eigrp_packet_rx_meta_t *meta) {
    srl_binding_t *b = srl_binding_get(eigrp);
    if (!b || !buffer || capacity == 0) return false;

    char cbuf[256];
    struct iovec iov = {.iov_base = buffer, .iov_len = capacity};
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cbuf,
        .msg_controllen = sizeof(cbuf)
    };

    ssize_t n = -1;
    if (b->fd >= 0) {
        n = recvmsg(b->fd, &msg, MSG_DONTWAIT);
    }
    if (n >= (ssize_t)sizeof(struct ip)) {
        struct ip *iph = (struct ip *)buffer;
        uint16_t hlen = (uint16_t)iph->ip_hl * 4U;
        if (n < (ssize_t)hlen) return false;

        uint16_t total_len = ntohs(iph->ip_len);
        if (total_len >= hlen && (ssize_t)total_len <= n) {
            n = (ssize_t)total_len;
        }

        if (src) {
            src->afi = EIGRP_AFI_IPV4;
            memcpy(src->bytes, &iph->ip_src, sizeof(iph->ip_src));
        }
        if (dst) {
            dst->afi = EIGRP_AFI_IPV4;
            memcpy(dst->bytes, &iph->ip_dst, sizeof(iph->ip_dst));
        }
        if (rx_len) *rx_len = (size_t)n;

        if (ifindex) *ifindex = 0;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
            if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(c);
                if (ifindex) *ifindex = (eigrp_ifindex_t)pi->ipi_ifindex;
                break;
            }
        }

        if (meta) {
            meta->ingress_vrf_id = eigrp->vrf_id;
            meta->network_header_length = hlen;
            meta->eigrp_length = (uint16_t)(n - hlen);
            meta->destination_multicast = (iph->ip_dst.s_addr == htonl(EIGRP_MULTICAST_ADDRESS)) ||
                                          IN_MULTICAST(ntohl(iph->ip_dst.s_addr));
        }

        if (ifindex && *ifindex == 0) {
            pthread_mutex_lock(&g_data_lock);
            for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
                if (strcmp(ci->netinst, b->netinst) != 0) continue;
                if (!ci->active) continue;
                if (memcmp(ci->address.address.bytes, &iph->ip_dst, sizeof(iph->ip_dst)) == 0) {
                    *ifindex = ci->ifindex;
                    break;
                }
            }
            if (*ifindex == 0) {
                uint32_t src_ip = ntohl(iph->ip_src.s_addr);
                for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
                    if (strcmp(ci->netinst, b->netinst) != 0) continue;
                    if (!ci->active) continue;
                    if (ci->address.prefix_length > 0 && ci->address.prefix_length <= 32) {
                        uint32_t if_ip;
                        memcpy(&if_ip, ci->address.address.bytes, sizeof(if_ip));
                        if_ip = ntohl(if_ip);
                        uint32_t mask = (0xffffffffU << (32U - ci->address.prefix_length));
                        if ((src_ip & mask) == (if_ip & mask)) {
                            *ifindex = ci->ifindex;
                            break;
                        }
                    }
                }
            }
            if (*ifindex == 0) {
                for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
                    if (strcmp(ci->netinst, b->netinst) == 0 &&
                        ci->active &&
                        ci->address.prefix_length > 0 &&
                        strcmp(ci->ifname, "system0.0") != 0 &&
                        strncmp(ci->ifname, "lo", 2) != 0) {
                        *ifindex = ci->ifindex;
                        break;
                    }
                }
            }
            pthread_mutex_unlock(&g_data_lock);
        }

        bool is_active_v4 = false;
        if (ifindex && *ifindex > 0) {
            pthread_mutex_lock(&g_data_lock);
            for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
                if (strcmp(ci->netinst, b->netinst) == 0 && ci->ifindex == *ifindex && ci->active) {
                    is_active_v4 = true;
                    break;
                }
            }
            pthread_mutex_unlock(&g_data_lock);
        }

        if (is_active_v4) {
            char s_str[INET_ADDRSTRLEN] = "", d_str[INET_ADDRSTRLEN] = "";
            inet_ntop(AF_INET, &iph->ip_src, s_str, sizeof(s_str));
            inet_ntop(AF_INET, &iph->ip_dst, d_str, sizeof(d_str));
            fprintf(stderr, "CSHIM RX (fd %s): src=%s dst=%s len=%zd ifindex=%u mcast=%d\n",
                    b->netinst, s_str, d_str, n, ifindex ? (unsigned)*ifindex : 0,
                    meta ? (int)meta->destination_multicast : 0);

            return true;
        }
    }

    // Fallback: Check AF_PACKET raw socket for packets dropped by SR Linux DP
    if (b->pkt_fd >= 0) {
        while (1) {
            uint8_t eth_buf[2048];
            struct sockaddr_ll sll;
            socklen_t sll_len = sizeof(sll);
            ssize_t pn = recvfrom(b->pkt_fd, eth_buf, sizeof(eth_buf), MSG_DONTWAIT,
                                  (struct sockaddr *)&sll, &sll_len);
            size_t eth_hdr_len = 14;
            if (pn < (ssize_t)(eth_hdr_len + sizeof(struct ip))) {
                break;
            }
            if (sll.sll_pkttype == PACKET_OUTGOING) {
                continue;
            }
            uint16_t eth_type = ntohs(*(uint16_t *)(eth_buf + 12));
            while (eth_type == 0x8100 || eth_type == 0x88a8) {
                eth_hdr_len += 4;
                if (pn < (ssize_t)(eth_hdr_len + sizeof(struct ip))) {
                    break;
                }
                eth_type = ntohs(*(uint16_t *)(eth_buf + eth_hdr_len - 2));
            }
            if (eth_type != 0x0800) {
                continue;
            }
            struct ip *iph = (struct ip *)(eth_buf + eth_hdr_len);
            // Must be IPv4, proto 88
            if (iph->ip_v != 4 || iph->ip_p != 88) {
                continue;
            }

            // Ensure packet was not originated by ourselves
            bool is_local = false;
            pthread_mutex_lock(&g_data_lock);
            for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
                if (strcmp(ci->netinst, b->netinst) == 0 &&
                    memcmp(ci->address.address.bytes, &iph->ip_src, sizeof(iph->ip_src)) == 0) {
                    is_local = true;
                    break;
                }
            }
            pthread_mutex_unlock(&g_data_lock);
            char s_str[INET_ADDRSTRLEN] = "", d_str[INET_ADDRSTRLEN] = "";
            inet_ntop(AF_INET, &iph->ip_src, s_str, sizeof(s_str));
            inet_ntop(AF_INET, &iph->ip_dst, d_str, sizeof(d_str));

            if (is_local) {
                continue;
            }

            uint16_t hlen = (uint16_t)iph->ip_hl * 4U;
            uint16_t total_ip_len = ntohs(iph->ip_len);
            if (total_ip_len < hlen || (ssize_t)total_ip_len > (pn - eth_hdr_len)) {
                fprintf(stderr, "CSHIM DROP: len mismatch total_ip_len=%u hlen=%u pn=%zd\n",
                        total_ip_len, hlen, pn);
                fflush(stderr);
                continue;
            }
            size_t ip_len = total_ip_len;
            if (ip_len > capacity) ip_len = capacity;
            memcpy(buffer, iph, ip_len);

            if (src) {
                src->afi = EIGRP_AFI_IPV4;
                memcpy(src->bytes, &iph->ip_src, sizeof(iph->ip_src));
            }
            if (dst) {
                dst->afi = EIGRP_AFI_IPV4;
                memcpy(dst->bytes, &iph->ip_dst, sizeof(iph->ip_dst));
            }
            if (rx_len) *rx_len = ip_len;

            char ifname_raw[IFNAMSIZ] = "";
            if_indextoname((unsigned)sll.sll_ifindex, ifname_raw);
            char mapped_name[64] = "";
            strncpy(mapped_name, ifname_raw, sizeof(mapped_name) - 1);
            char *last_dash = strrchr(mapped_name, '-');
            if (last_dash && isdigit((unsigned char)*(last_dash + 1))) {
                *last_dash = '.';
            }

            // Match interface in g_interfaces:
            // 1. Try destination IP match (for unicast to interface IP)
            eigrp_ifindex_t found_idx = 0;
            pthread_mutex_lock(&g_data_lock);
            for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
                if (strcmp(ci->netinst, b->netinst) != 0) continue;
                if (!ci->active) continue;
                if (ci->address.prefix_length > 0 && memcmp(ci->address.address.bytes, &iph->ip_dst, sizeof(iph->ip_dst)) == 0) {
                    found_idx = ci->ifindex;
                    break;
                }
            }
            // 2. Try mapped interface name from packet socket
            if (found_idx == 0 && mapped_name[0]) {
                for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
                    if (strcmp(ci->netinst, b->netinst) != 0) continue;
                    if (!ci->active) continue;
                    if (srl_match_ifname(ci->ifname, mapped_name)) {
                        found_idx = ci->ifindex;
                        break;
                    }
                }
            }
            // 3. Try subnet match on source IP (for multicast/broadcast or point-to-point)
            if (found_idx == 0) {
                uint32_t src_ip = ntohl(iph->ip_src.s_addr);
                for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
                    if (strcmp(ci->netinst, b->netinst) != 0) continue;
                    if (!ci->active) continue;
                    if (ci->address.prefix_length > 0 && ci->address.prefix_length <= 32) {
                        uint32_t if_ip;
                        memcpy(&if_ip, ci->address.address.bytes, sizeof(if_ip));
                        if_ip = ntohl(if_ip);
                        uint32_t mask = (0xffffffffU << (32U - ci->address.prefix_length));
                        if ((src_ip & mask) == (if_ip & mask)) {
                            found_idx = ci->ifindex;
                            break;
                        }
                    }
                }
            }
            pthread_mutex_unlock(&g_data_lock);

            if (found_idx == 0) {
                // Not for this VRF instance
                continue;
            }

            if (ifindex) *ifindex = found_idx;
            if (meta) {
                meta->ingress_vrf_id = eigrp->vrf_id;
                meta->network_header_length = hlen;
                meta->eigrp_length = (uint16_t)(ip_len - hlen);
                meta->destination_multicast = (iph->ip_dst.s_addr == htonl(EIGRP_MULTICAST_ADDRESS)) ||
                                              IN_MULTICAST(ntohl(iph->ip_dst.s_addr));
            }

            fprintf(stderr, "CSHIM RX (pkt_fd %s): src=%s dst=%s len=%zu ifindex=%u mcast=%d\n",
                    b->netinst, s_str, d_str, ip_len, (unsigned)found_idx, (int)meta->destination_multicast);
            fflush(stderr);

            return true;
        }
    }

    return false;
}

int eigrp_sys_ipv6_packet_send(eigrp_instance_t *eigrp, eigrp_intf_t *ei,
                               const eigrp_address_t *dst, const uint8_t *payload, size_t length) {
    int fd = srl_socket_fd_get(eigrp);
    if (fd < 0 || !ei || !dst || !payload) return -1;

    struct sockaddr_in6 sin6;
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    memcpy(&sin6.sin6_addr, dst->bytes, 16);
    sin6.sin6_scope_id = (uint32_t)eigrp_intf_ifindex(ei);

    eigrp_prefix_t local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    eigrp_intf_address_read(ei, &local_addr);

    if (IN6_IS_ADDR_MULTICAST(&sin6.sin6_addr)) {
        eigrp_sys_multicast_interface_update(EIGRP_SET, eigrp, ei);
    }

    struct iovec iov = {
        .iov_base = (void *)payload,
        .iov_len = length,
    };

    char cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    memset(cbuf, 0, sizeof(cbuf));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sin6;
    msg.msg_namelen = sizeof(sin6);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
    pktinfo->ipi6_ifindex = (int)eigrp_intf_ifindex(ei);
    if (local_addr.address.afi == EIGRP_AFI_IPV6 && !IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)local_addr.address.bytes)) {
        memcpy(&pktinfo->ipi6_addr, local_addr.address.bytes, 16);
    }

    int flags = 0;
    if (!IN6_IS_ADDR_MULTICAST(&sin6.sin6_addr)) {
        flags = MSG_DONTROUTE;
    }

    ssize_t ret = sendmsg(fd, &msg, flags);
    if (ret < 0) {
        char dst_str[INET6_ADDRSTRLEN] = "";
        inet_ntop(AF_INET6, &sin6.sin6_addr, dst_str, sizeof(dst_str));
        fprintf(stderr, "CSHIM TX ERR V6: sendmsg fd=%d ifindex=%u dst=%s len=%zu errno=%d (%s)\n",
                fd, (unsigned)eigrp_intf_ifindex(ei), dst_str, length, errno, strerror(errno));
    }
    return (int)ret;
}

bool eigrp_sys_ipv6_packet_receive(eigrp_instance_t *eigrp, uint8_t *buffer, size_t capacity,
                                   size_t *rx_len, eigrp_ifindex_t *ifindex, eigrp_address_t *src,
                                   eigrp_address_t *dst, eigrp_packet_rx_meta_t *meta) {
    srl_binding_t *b = srl_binding_get(eigrp);
    if (!b || !buffer || capacity == 0) return false;

    char cbuf[256];
    struct sockaddr_in6 from;
    memset(&from, 0, sizeof(from));
    struct iovec iov = {.iov_base = buffer, .iov_len = capacity};
    struct msghdr msg = {
        .msg_name = &from,
        .msg_namelen = sizeof(from),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cbuf,
        .msg_controllen = sizeof(cbuf)
    };

    ssize_t n = -1;
    if (b->fd >= 0) {
        n = recvmsg(b->fd, &msg, MSG_DONTWAIT);
    }
    if (n > 0) {
        bool is_self = false;
        pthread_mutex_lock(&g_data_lock);
        for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
            if (strcmp(ci->netinst, b->netinst) == 0) {
                if (memcmp(ci->address_v6.address.bytes, &from.sin6_addr, 16) == 0 ||
                    memcmp(ci->global_v6.address.bytes, &from.sin6_addr, 16) == 0) {
                    is_self = true;
                    break;
                }
            }
        }
        pthread_mutex_unlock(&g_data_lock);
        if (!is_self) {
            if (src) {
                src->afi = EIGRP_AFI_IPV6;
                memcpy(src->bytes, &from.sin6_addr, 16);
            }
            if (rx_len) *rx_len = (size_t)n;

            eigrp_ifindex_t rx_idx = (eigrp_ifindex_t)from.sin6_scope_id;
            struct in6_addr dst_ip = {0};
            bool is_mcast = false;

            for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
                    struct in6_pktinfo *pkt = (struct in6_pktinfo *)CMSG_DATA(cmsg);
                    if (pkt->ipi6_ifindex > 0) {
                        rx_idx = (eigrp_ifindex_t)pkt->ipi6_ifindex;
                    }
                    dst_ip = pkt->ipi6_addr;
                    is_mcast = IN6_IS_ADDR_MULTICAST(&dst_ip);
                }
            }

            bool is_active_v6 = false;
            if (rx_idx > 0) {
                pthread_mutex_lock(&g_data_lock);
                for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
                    if (strcmp(ci->netinst, b->netinst) == 0 && ci->ifindex == rx_idx && ci->active_v6) {
                        is_active_v6 = true;
                        break;
                    }
                }
                pthread_mutex_unlock(&g_data_lock);
            }
            if (is_active_v6) {
                if (dst) {
                    dst->afi = EIGRP_AFI_IPV6;
                    memcpy(dst->bytes, &dst_ip, 16);
                }
                if (ifindex) *ifindex = rx_idx;

                if (meta) {
                    meta->ingress_vrf_id = eigrp->vrf_id;
                    meta->network_header_length = 0;
                    meta->eigrp_length = (uint16_t)n;
                    meta->destination_multicast = is_mcast;
                }
                return true;
            }
        }
    }

    // Fallback: Check AF_PACKET raw socket for packets dropped by SR Linux DP
    if (b->pkt_fd >= 0) {
        while (1) {
            uint8_t eth_buf[2048];
            struct sockaddr_ll sll;
            socklen_t sll_len = sizeof(sll);
            ssize_t pn = recvfrom(b->pkt_fd, eth_buf, sizeof(eth_buf), MSG_DONTWAIT,
                                  (struct sockaddr *)&sll, &sll_len);
            size_t eth_hdr_len = 14;
            if (pn < (ssize_t)(eth_hdr_len + 40)) {
                break;
            }
            if (sll.sll_pkttype == PACKET_OUTGOING) {
                continue;
            }
            uint16_t eth_type = ntohs(*(uint16_t *)(eth_buf + 12));
            while (eth_type == 0x8100 || eth_type == 0x88a8) {
                eth_hdr_len += 4;
                if (pn < (ssize_t)(eth_hdr_len + 40)) {
                    break;
                }
                eth_type = ntohs(*(uint16_t *)(eth_buf + eth_hdr_len - 2));
            }
            if (eth_type != 0x86dd) continue;

            uint8_t nxt = eth_buf[eth_hdr_len + 6];
            if (nxt != 88) continue;

            uint16_t payload_len = ntohs(*(uint16_t *)(eth_buf + eth_hdr_len + 4));
            if ((ssize_t)(eth_hdr_len + 40 + payload_len) > pn) continue;

            struct in6_addr *src_ip6 = (struct in6_addr *)(eth_buf + eth_hdr_len + 8);
            struct in6_addr *dst_ip6 = (struct in6_addr *)(eth_buf + eth_hdr_len + 24);

            bool is_local = false;
            pthread_mutex_lock(&g_data_lock);
            for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
                if (strcmp(ci->netinst, b->netinst) == 0) {
                    if (memcmp(ci->address_v6.address.bytes, src_ip6, 16) == 0 ||
                        memcmp(ci->global_v6.address.bytes, src_ip6, 16) == 0) {
                        is_local = true;
                        break;
                    }
                }
            }
            pthread_mutex_unlock(&g_data_lock);
            if (is_local) continue;

            char root_ifname[IFNAMSIZ] = "";
            if_indextoname(sll.sll_ifindex, root_ifname);
            char mapped_name[IFNAMSIZ] = "";
            strncpy(mapped_name, root_ifname, sizeof(mapped_name) - 1);
            char *last_dash = strrchr(mapped_name, '-');
            if (last_dash && isdigit((unsigned char)*(last_dash + 1))) {
                *last_dash = '.';
            }

            eigrp_ifindex_t found_idx = 0;
            pthread_mutex_lock(&g_data_lock);
            for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
                if (strcmp(ci->netinst, b->netinst) != 0) continue;
                if (!ci->active_v6) continue;
                if (memcmp(ci->address_v6.address.bytes, dst_ip6, 16) == 0 ||
                    memcmp(ci->global_v6.address.bytes, dst_ip6, 16) == 0) {
                    found_idx = ci->ifindex;
                    break;
                }
                if (mapped_name[0] && srl_match_ifname(ci->ifname, mapped_name)) {
                    found_idx = ci->ifindex;
                    break;
                }
            }
            if (found_idx == 0 && IN6_IS_ADDR_MULTICAST(dst_ip6)) {
                for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
                    if (strcmp(ci->netinst, b->netinst) != 0) continue;
                    if (!ci->active_v6) continue;
                    if (ci->address_v6.address.afi == EIGRP_AFI_IPV6 &&
                        strcmp(ci->ifname, "system0.0") != 0 &&
                        strncmp(ci->ifname, "lo", 2) != 0) {
                        found_idx = ci->ifindex;
                        break;
                    }
                }
            }
            pthread_mutex_unlock(&g_data_lock);

            if (found_idx == 0) continue;

            size_t copy_len = payload_len;
            if (copy_len > capacity) copy_len = capacity;
            memcpy(buffer, eth_buf + eth_hdr_len + 40, copy_len);

            if (src) {
                src->afi = EIGRP_AFI_IPV6;
                memcpy(src->bytes, src_ip6, 16);
            }
            if (dst) {
                dst->afi = EIGRP_AFI_IPV6;
                memcpy(dst->bytes, dst_ip6, 16);
            }
            if (rx_len) *rx_len = copy_len;
            if (ifindex) *ifindex = found_idx;
            if (meta) {
                meta->ingress_vrf_id = eigrp->vrf_id;
                meta->network_header_length = 0;
                meta->eigrp_length = (uint16_t)copy_len;
                meta->destination_multicast = IN6_IS_ADDR_MULTICAST(dst_ip6);
            }

            char s_str6[INET6_ADDRSTRLEN] = "", d_str6[INET6_ADDRSTRLEN] = "";
            inet_ntop(AF_INET6, src_ip6, s_str6, sizeof(s_str6));
            inet_ntop(AF_INET6, dst_ip6, d_str6, sizeof(d_str6));
            fprintf(stderr, "CSHIM RX V6 (pkt_fd %s): src=%s dst=%s len=%zu ifindex=%u mcast=%d\n",
                    b->netinst, s_str6, d_str6, copy_len, (unsigned)found_idx, (int)IN6_IS_ADDR_MULTICAST(dst_ip6));

            return true;
        }
    }
    return false;
}

int eigrp_sys_packet_send(eigrp_instance_t *e, eigrp_intf_t *ei, const eigrp_address_t *dst,
                          const uint8_t *payload, size_t len) {
    if (!dst) return -1;
    if (dst->afi == EIGRP_AFI_IPV6 || eigrp_instance_afi(e) == EIGRP_AFI_IPV6) {
        return eigrp_sys_ipv6_packet_send(e, ei, dst, payload, len);
    }
    return eigrp_sys_ipv4_packet_send(e, ei, dst, payload, len);
}

bool eigrp_sys_packet_receive(eigrp_instance_t *e, uint8_t *b, size_t cap, size_t *r,
                              eigrp_ifindex_t *i, eigrp_address_t *s, eigrp_address_t *d,
                              eigrp_packet_rx_meta_t *m) {
    if (eigrp_instance_afi(e) == EIGRP_AFI_IPV6) {
        return eigrp_sys_ipv6_packet_receive(e, b, cap, r, i, s, d, m);
    }
    return eigrp_sys_ipv4_packet_receive(e, b, cap, r, i, s, d, m);
}

/* ------------------------------------------------------------------------
 * Policy & Filter Stubs
 * ------------------------------------------------------------------------ */

void eigrp_sys_policy_init(void) {}
void eigrp_sys_policy_finish(void) {}
eigrp_result_t eigrp_sys_policy_instance_create(eigrp_instance_t *e) { (void)e; return EIGRP_RESULT_SUCCESS; }
void eigrp_sys_policy_instance_delete(eigrp_instance_t *e) { (void)e; }

eigrp_result_t eigrp_sys_filter_evaluate(eigrp_instance_t *e, eigrp_distribute_list_type_t t,
                                         const char *n, const eigrp_prefix_t *p,
                                         eigrp_filter_decision_t *decision) {
    (void)e; (void)t; (void)n; (void)p;
    if (decision) *decision = EIGRP_FILTER_DECISION_PERMIT;
    return EIGRP_RESULT_SUCCESS;
}

eigrp_result_t eigrp_sys_redistribute_route_map_evaluate(eigrp_instance_t *e, const char *n,
                                                         const eigrp_rib_route_t *r,
                                                         eigrp_filter_decision_t *decision) {
    (void)e; (void)n; (void)r;
    if (decision) *decision = EIGRP_FILTER_DECISION_PERMIT;
    return EIGRP_RESULT_SUCCESS;
}

eigrp_result_t eigrp_sys_summary_leak_map_evaluate(eigrp_instance_t *e, const char *n,
                                                   const eigrp_prefix_t *p,
                                                   eigrp_filter_decision_t *decision) {
    (void)e; (void)n; (void)p;
    if (decision) *decision = EIGRP_FILTER_DECISION_DENY;
    return EIGRP_RESULT_SUCCESS;
}

/* ------------------------------------------------------------------------
 * Interfaces, Walking & Netns Scanning
 * ------------------------------------------------------------------------ */

eigrp_result_t eigrp_sys_interface_walk(eigrp_instance_t *e, eigrp_sys_interface_walk_cb cb, void *arg) {
    if (!cb) return EIGRP_RESULT_INVALID_ARGUMENT;
    const char *ni = e ? srl_netinst_by_instance(e) : "default";

    pthread_mutex_lock(&g_data_lock);
    size_t count = 0;
    for (srl_intf_t *c = g_interfaces; c; c = c->next) {
        if (strcmp(c->netinst, ni) != 0) continue;
        if (c->address.prefix_length > 0) count++;
        if (c->address_v6.address.afi == EIGRP_AFI_IPV6) count++;
    }
    eigrp_intf_runtime_state_t *sts = NULL;
    if (count > 0) {
        sts = calloc(count, sizeof(*sts));
        size_t i = 0;
        for (srl_intf_t *c = g_interfaces; c && i < count; c = c->next) {
            if (strcmp(c->netinst, ni) != 0) continue;
            if (c->address.prefix_length > 0) {
                sts[i].interface_name = strdup(c->ifname);
                sts[i].ifindex = c->ifindex;
                sts[i].address = c->address;
                sts[i].type = 1; // multi-access
                sts[i].secondary = false;
                sts[i].operative = true;
                sts[i].bandwidth = c->bandwidth;
                sts[i].mtu = c->mtu;
                i++;
            }
            if (c->address_v6.address.afi == EIGRP_AFI_IPV6 && i < count) {
                sts[i].interface_name = strdup(c->ifname);
                sts[i].ifindex = c->ifindex;
                sts[i].address = c->address_v6;
                sts[i].type = 1; // multi-access
                sts[i].secondary = false;
                sts[i].operative = true;
                sts[i].bandwidth = c->bandwidth;
                sts[i].mtu = c->mtu;
                i++;
            }
        }
        count = i;
    }
    pthread_mutex_unlock(&g_data_lock);

    if (sts) {
        for (size_t i = 0; i < count; i++) {
            cb(&sts[i], arg);
            free((void *)sts[i].interface_name);
        }
        free(sts);
    }

    return EIGRP_RESULT_SUCCESS;
}

void srl_resolve_v6_gateway(const char *netinst, eigrp_ifindex_t ifidx, char *nh_str, size_t max_len) {
    if (!nh_str || max_len < INET6_ADDRSTRLEN) return;
    struct in6_addr target_ll;
    if (inet_pton(AF_INET6, nh_str, &target_ll) != 1) return;
    if (!IN6_IS_ADDR_LINKLOCAL(&target_ll)) {
        return;
    }

    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    int saved_ns = -1;
    bool in_ns = (srl_netns_enter(ni, &saved_ns) == 0);

    bool resolved = false;
    int nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_fd >= 0) {
        struct {
            struct nlmsghdr n;
            struct ndmsg ndm;
        } req;
        memset(&req, 0, sizeof(req));
        req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
        req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        req.n.nlmsg_type = RTM_GETNEIGH;
        req.ndm.ndm_family = AF_INET6;

        struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };
        setsockopt(nl_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (send(nl_fd, &req, req.n.nlmsg_len, 0) >= 0) {
            typedef struct {
                struct in6_addr ip;
                uint8_t mac[6];
                bool has_mac;
                bool is_ll;
            } neigh_cache_t;

            neigh_cache_t cache[128];
            int cache_count = 0;

            char buf[8192];
            ssize_t len;
            bool done = false;

            while (!done && (len = recv(nl_fd, buf, sizeof(buf), 0)) > 0) {
                struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
                for (; NLMSG_OK(nlh, (size_t)len); nlh = NLMSG_NEXT(nlh, len)) {
                    if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
                        done = true;
                        break;
                    }
                    if (nlh->nlmsg_type != RTM_NEWNEIGH) continue;

                    struct ndmsg *ndm = NLMSG_DATA(nlh);
                    if (ndm->ndm_family != AF_INET6) continue;
                    if (ifidx != 0 && ndm->ndm_ifindex != (int)ifidx) continue;

                    struct rtattr *rta = (struct rtattr *)(((char *)ndm) + NLMSG_ALIGN(sizeof(struct ndmsg)));
                    int rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));

                    struct in6_addr entry_ip;
                    memset(&entry_ip, 0, sizeof(entry_ip));
                    bool has_ip = false;
                    uint8_t entry_mac[6];
                    bool has_mac = false;

                    for (; RTA_OK(rta, rtalen); rta = RTA_NEXT(rta, rtalen)) {
                        if (rta->rta_type == NDA_DST && RTA_PAYLOAD(rta) == 16) {
                            memcpy(&entry_ip, RTA_DATA(rta), 16);
                            has_ip = true;
                        } else if (rta->rta_type == NDA_LLADDR && RTA_PAYLOAD(rta) == 6) {
                            memcpy(entry_mac, RTA_DATA(rta), 6);
                            has_mac = true;
                        }
                    }

                    if (has_ip && cache_count < 128) {
                        cache[cache_count].ip = entry_ip;
                        cache[cache_count].is_ll = IN6_IS_ADDR_LINKLOCAL(&entry_ip);
                        cache[cache_count].has_mac = has_mac;
                        if (has_mac) {
                            memcpy(cache[cache_count].mac, entry_mac, 6);
                        }
                        cache_count++;
                    }
                }
            }

            // Find target link-local MAC
            uint8_t match_mac[6];
            bool found_mac = false;
            for (int i = 0; i < cache_count; i++) {
                if (cache[i].is_ll && cache[i].has_mac &&
                    memcmp(&cache[i].ip, &target_ll, 16) == 0) {
                    memcpy(match_mac, cache[i].mac, 6);
                    found_mac = true;
                    break;
                }
            }

            if (found_mac) {
                for (int i = 0; i < cache_count; i++) {
                    if (!cache[i].is_ll && cache[i].has_mac &&
                        !IN6_IS_ADDR_MULTICAST(&cache[i].ip) &&
                        memcmp(cache[i].mac, match_mac, 6) == 0) {
                        inet_ntop(AF_INET6, &cache[i].ip, nh_str, max_len);
                        resolved = true;
                        break;
                    }
                }
            }
        }
        close(nl_fd);
    }

    if (in_ns) {
        srl_netns_leave(saved_ns);
    }

    if (resolved) return;

    // Fallback: Check local interface subnet and derive peer for /127 or standard /64 peering
    pthread_mutex_lock(&g_data_lock);
    for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
        if (strcmp(ci->netinst, ni) != 0) continue;
        if ((ifidx == 0 || ci->ifindex == ifidx) &&
            ci->global_v6.address.afi == EIGRP_AFI_IPV6 &&
            ci->global_v6.prefix_length > 0) {
            struct in6_addr peer_ip;
            memcpy(&peer_ip, ci->global_v6.address.bytes, 16);
            if (ci->global_v6.prefix_length == 127) {
                peer_ip.s6_addr[15] ^= 1;
                inet_ntop(AF_INET6, &peer_ip, nh_str, max_len);
                resolved = true;
                break;
            } else if (ci->global_v6.prefix_length <= 64) {
                if (peer_ip.s6_addr[15] == 1) {
                    peer_ip.s6_addr[15] = 2;
                    inet_ntop(AF_INET6, &peer_ip, nh_str, max_len);
                    resolved = true;
                    break;
                } else if (peer_ip.s6_addr[15] == 2) {
                    peer_ip.s6_addr[15] = 1;
                    inet_ntop(AF_INET6, &peer_ip, nh_str, max_len);
                    resolved = true;
                    break;
                }
            }
        }
    }
    pthread_mutex_unlock(&g_data_lock);
}

int srlShimInterfaceAdd(const char *netinst, const char *ifname, const char *ip_addr, uint32_t prefixlen) {
    if (!ifname || !ip_addr) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    struct in_addr in;
    if (inet_pton(AF_INET, ip_addr, &in) != 1) return -1;

    // Resolve ifindex inside netns if available
    eigrp_ifindex_t idx = 0;
    char dev_name[IFNAMSIZ] = {0};
    int saved_ns = -1;
    bool in_ns = (srl_netns_enter(ni, &saved_ns) == 0);
    if (in_ns) {
        idx = srl_resolve_ifindex_dev(ifname, dev_name, sizeof(dev_name));
    }
    if (idx == 0) {
        idx = srl_resolve_ifindex_dev(ifname, dev_name, sizeof(dev_name));
    }
    if (idx == 0) {
        if (in_ns) srl_netns_leave(saved_ns);
        return -1;
    }

    pthread_mutex_lock(&g_data_lock);
    srl_intf_t *found = NULL;
    for (srl_intf_t *cur = g_interfaces; cur; cur = cur->next) {
        if (strcmp(cur->netinst, ni) == 0 && strcmp(cur->ifname, ifname) == 0) {
            found = cur;
            break;
        }
    }
    if (!found) {
        found = calloc(1, sizeof(*found));
        strncpy(found->netinst, ni, sizeof(found->netinst) - 1);
        strncpy(found->ifname, ifname, sizeof(found->ifname) - 1);
        found->next = g_interfaces;
        g_interfaces = found;
    }
    found->ifindex = idx;
    found->address.address.afi = EIGRP_AFI_IPV4;
    memcpy(found->address.address.bytes, &in, 4);
    found->address.prefix_length = (uint8_t)prefixlen;
    // Dynamically detect interface MTU inside netns if possible
    found->mtu = 1500;
    found->bandwidth = 1000000; // default 1 Gbps (Kbps)

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, dev_name[0] ? dev_name : ifname, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFMTU, &ifr) == 0 && ifr.ifr_mtu > 0) {
            found->mtu = (uint32_t)ifr.ifr_mtu;
        }
        close(sock);
    }

    if (in_ns) {
        srl_netns_leave(saved_ns);
    }

    // Try reading speed from /sys/class/net/<ifname>/speed (Mbps -> Kbps)
    char speed_path[256];
    snprintf(speed_path, sizeof(speed_path), "/sys/class/net/%s/speed", dev_name[0] ? dev_name : ifname);
    FILE *sf = fopen(speed_path, "r");
    if (sf) {
        long mbps = 0;
        if (fscanf(sf, "%ld", &mbps) == 1 && mbps > 0) {
            found->bandwidth = (uint32_t)(mbps * 1000);
        }
        fclose(sf);
    }
    pthread_mutex_unlock(&g_data_lock);

    // Notify EIGRP about the interface
    eigrp_intf_runtime_state_t st;
    memset(&st, 0, sizeof(st));
    st.interface_name = found->ifname;
    st.ifindex = found->ifindex;
    st.address = found->address;
    st.type = 1;
    st.secondary = false;
    st.operative = true;
    st.bandwidth = found->bandwidth;
    st.mtu = found->mtu;
    eigrp_sys_intf_update((eigrp_vrf_id_t)srl_vrf_id_get(ni), &st);

    return 0;
}

int srlShimInterfaceAddV6(const char *netinst, const char *ifname, const char *ip_addr, uint32_t prefixlen) {
    if (!ifname || !ip_addr) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    struct in6_addr in6;
    if (inet_pton(AF_INET6, ip_addr, &in6) != 1) return -1;

    eigrp_ifindex_t idx = 0;
    char dev_name[IFNAMSIZ] = {0};
    int saved_ns = -1;
    bool in_ns = (srl_netns_enter(ni, &saved_ns) == 0);
    if (in_ns) {
        idx = srl_resolve_ifindex_dev(ifname, dev_name, sizeof(dev_name));
    }
    if (idx == 0) {
        idx = srl_resolve_ifindex_dev(ifname, dev_name, sizeof(dev_name));
    }
    if (idx == 0) {
        if (in_ns) srl_netns_leave(saved_ns);
        return -1;
    }

    pthread_mutex_lock(&g_data_lock);
    srl_intf_t *found = NULL;
    for (srl_intf_t *cur = g_interfaces; cur; cur = cur->next) {
        if (strcmp(cur->netinst, ni) == 0 && strcmp(cur->ifname, ifname) == 0) {
            found = cur;
            break;
        }
    }
    if (!found) {
        found = calloc(1, sizeof(*found));
        strncpy(found->netinst, ni, sizeof(found->netinst) - 1);
        strncpy(found->ifname, ifname, sizeof(found->ifname) - 1);
        found->next = g_interfaces;
        g_interfaces = found;
    }
    found->ifindex = idx;
    if (found->mtu == 0) found->mtu = 1500;
    if (found->bandwidth == 0) found->bandwidth = 1000000;

    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock >= 0) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, dev_name[0] ? dev_name : ifname, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFMTU, &ifr) == 0 && ifr.ifr_mtu > 0) {
            found->mtu = (uint32_t)ifr.ifr_mtu;
        }
        close(sock);
    }

    if (in_ns) {
        srl_netns_leave(saved_ns);
    }

    char speed_path[256];
    snprintf(speed_path, sizeof(speed_path), "/sys/class/net/%s/speed", dev_name[0] ? dev_name : ifname);
    FILE *sf = fopen(speed_path, "r");
    if (sf) {
        long mbps = 0;
        if (fscanf(sf, "%ld", &mbps) == 1 && mbps > 0) {
            found->bandwidth = (uint32_t)(mbps * 1000);
        }
        fclose(sf);
    }

    bool is_ll = IN6_IS_ADDR_LINKLOCAL(&in6);
    if (is_ll) {
        found->address_v6.address.afi = EIGRP_AFI_IPV6;
        memcpy(found->address_v6.address.bytes, &in6, 16);
        found->address_v6.prefix_length = (uint8_t)prefixlen;
    } else {
        found->global_v6.address.afi = EIGRP_AFI_IPV6;
        memcpy(found->global_v6.address.bytes, &in6, 16);
        found->global_v6.prefix_length = (uint8_t)prefixlen;
        if (found->address_v6.address.afi != EIGRP_AFI_IPV6) {
            found->address_v6 = found->global_v6;
        }
    }

    eigrp_intf_runtime_state_t st;
    memset(&st, 0, sizeof(st));
    st.interface_name = found->ifname;
    st.ifindex = found->ifindex;
    st.address = found->address_v6;
    st.type = 1;
    st.secondary = false;
    st.operative = true;
    st.bandwidth = found->bandwidth;
    st.mtu = found->mtu;
    pthread_mutex_unlock(&g_data_lock);

    eigrp_sys_intf_update((eigrp_vrf_id_t)srl_vrf_id_get(ni), &st);

    return 0;
}

int srlShimInterfacesScan(const char *netinst) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    int saved_ns = -1;
    int entered = srl_netns_enter(ni, &saved_ns);
    if (entered < 0) {
        return -1;
    }

    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) != 0) {
        srl_netns_leave(saved_ns);
        return -1;
    }

    for (struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (strcmp(ifa->ifa_name, "gateway") == 0 || strcmp(ifa->ifa_name, "lo") == 0) continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            char ip_str[INET_ADDRSTRLEN];
            if (!inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str))) continue;
            if (sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) continue;

            uint32_t prefixlen = 32;
            if (ifa->ifa_netmask) {
                struct sockaddr_in *nm = (struct sockaddr_in *)ifa->ifa_netmask;
                uint32_t mask = ntohl(nm->sin_addr.s_addr);
                prefixlen = 0;
                while (mask & 0x80000000U) {
                    prefixlen++;
                    mask <<= 1;
                }
            }
            srlShimInterfaceAdd(ni, ifa->ifa_name, ip_str, prefixlen);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) || IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) continue;
            char ip6_str[INET6_ADDRSTRLEN];
            if (!inet_ntop(AF_INET6, &sin6->sin6_addr, ip6_str, sizeof(ip6_str))) continue;

            uint32_t prefixlen = 64;
            if (ifa->ifa_netmask) {
                struct sockaddr_in6 *nm6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
                prefixlen = 0;
                for (int b = 0; b < 16; b++) {
                    uint8_t byte = nm6->sin6_addr.s6_addr[b];
                    while (byte & 0x80) {
                        prefixlen++;
                        byte <<= 1;
                    }
                }
            }
            srlShimInterfaceAddV6(ni, ifa->ifa_name, ip6_str, prefixlen);
        }
    }

    freeifaddrs(ifap);
    srl_netns_leave(saved_ns);
    return 0;
}


/* ------------------------------------------------------------------------
 * Host Shim APIs Called from Go
 * ------------------------------------------------------------------------ */

int srlShimInit(void) {
    srl_netns_restore_root();
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    eigrp_sys_runtime_init();
    eigrp_init();
    return 0;
}

void srlShimFinish(void) {
    eigrp_terminate();
    eigrp_sys_runtime_finish();
}

int srlShimInstanceCreate(const char *netinst, uint16_t asn, const char *router_id) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    uint32_t vrf_id = srl_vrf_id_get(ni);

    pthread_mutex_lock(&g_data_lock);
    strncpy(g_pending_netinst, ni, sizeof(g_pending_netinst) - 1);
    g_pending_netinst[sizeof(g_pending_netinst) - 1] = '\0';
    pthread_mutex_unlock(&g_data_lock);

    // If an existing instance with this netinst is already created, only recreate if ASN changed
    eigrp_instance_t *existing = srl_instance_get_afi(ni, EIGRP_AFI_IPV4);
    if (existing) {
        if (existing->AS == asn) {
            if (router_id && router_id[0]) {
                struct in_addr r_addr;
                if (inet_pton(AF_INET, router_id, &r_addr) == 1) {
                    eigrp_instance_context_t ctx;
                    memset(&ctx, 0, sizeof(ctx));
                    ctx.runtime = existing;
                    eigrp_instance_router_id_update(EIGRP_SET, &ctx, ntohl(r_addr.s_addr));
                }
            }
            pthread_mutex_lock(&g_data_lock);
            g_pending_netinst[0] = '\0';
            pthread_mutex_unlock(&g_data_lock);
            return 0;
        }
        eigrp_instance_classic_delete(existing);
    }

    eigrp_instance_t *runtime = NULL;
    eigrp_result_t res = eigrp_instance_classic_create(asn, (eigrp_vrf_id_t)vrf_id, &runtime);
    pthread_mutex_lock(&g_data_lock);
    g_pending_netinst[0] = '\0';
    pthread_mutex_unlock(&g_data_lock);
    if (res != EIGRP_RESULT_SUCCESS || !runtime) {
        return -1;
    }

    if (router_id && router_id[0]) {
        struct in_addr r_addr;
        if (inet_pton(AF_INET, router_id, &r_addr) == 1) {
            eigrp_instance_context_t ctx;
            memset(&ctx, 0, sizeof(ctx));
            ctx.runtime = runtime;
            eigrp_instance_router_id_update(EIGRP_SET, &ctx, ntohl(r_addr.s_addr));
        }
    }

    // Scan interfaces in netns now that the instance is ready to receive interface events
    srlShimInterfacesScan(ni);

    return 0;
}

int srlShimInstanceDelete(const char *netinst) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    pthread_mutex_lock(&g_data_lock);
    g_pending_netinst[0] = '\0';
    for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
        if (strcmp(ci->netinst, ni) == 0) {
            ci->active = false;
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    eigrp_instance_t *runtime = srl_instance_get_afi(ni, EIGRP_AFI_IPV4);
    if (runtime) {
        eigrp_instance_classic_delete(runtime);
    }
    return 0;
}

int srlShimNetworkAdd(const char *netinst, const char *prefix) {
    if (!prefix) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    // Re-scan interfaces in case any new ones appeared
    srlShimInterfacesScan(ni);

    pthread_mutex_lock(&g_data_lock);
    eigrp_instance_t *runtime = srl_instance_get_afi(ni, EIGRP_AFI_IPV4);
    if (!runtime) {
        pthread_mutex_unlock(&g_data_lock);
        return -1;
    }

    char pfx_copy[128];
    strncpy(pfx_copy, prefix, sizeof(pfx_copy) - 1);
    pfx_copy[sizeof(pfx_copy) - 1] = '\0';

    char *slash = strchr(pfx_copy, '/');
    uint8_t plen = 32;
    if (slash) {
        *slash = '\0';
        plen = (uint8_t)atoi(slash + 1);
    }

    eigrp_prefix_t pfx;
    memset(&pfx, 0, sizeof(pfx));
    pfx.address.afi = EIGRP_AFI_IPV4;
    if (inet_pton(AF_INET, pfx_copy, pfx.address.bytes) != 1) {
        pthread_mutex_unlock(&g_data_lock);
        return -1;
    }
    pthread_mutex_unlock(&g_data_lock);

    eigrp_instance_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.runtime = runtime;

    eigrp_result_t res = eigrp_network_create(&ctx, &pfx);
    if (res != EIGRP_RESULT_SUCCESS) {
        return -1;
    }

    uint32_t net_ip = 0;
    memcpy(&net_ip, pfx.address.bytes, 4);
    uint32_t mask = (plen == 0) ? 0 : htonl(~((1ULL << (32 - plen)) - 1));
    pthread_mutex_lock(&g_data_lock);
    for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
        if (strcmp(ci->netinst, ni) != 0) continue;
        uint32_t ci_ip = 0;
        memcpy(&ci_ip, ci->address.address.bytes, 4);
        if ((ci_ip & mask) == (net_ip & mask)) {
            ci->active = true;
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    return 0;
}

static eigrp_result_t srl_nbr_iter_cb(const eigrp_nbr_state_t *st, void *arg) {
    const char *ni = (const char *)arg;
    if (!ni) ni = "default";
    if (!st) return EIGRP_RESULT_SUCCESS;
    char ip_str[64] = "";
    int afi = (st->address.afi == EIGRP_AFI_IPV6) ? AF_INET6 : AF_INET;
    inet_ntop(afi, st->address.bytes, ip_str, sizeof(ip_str));

    char auth_mode[32] = "none";
    bool is_passive = false;
    pthread_mutex_lock(&g_data_lock);
    for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
        if (strcmp(ci->netinst, ni) == 0 && ci->ifname[0] && st->interface_name &&
            srl_match_ifname(ci->ifname, st->interface_name)) {
            if (st->address.afi == EIGRP_AFI_IPV6) {
                if (ci->passive_v6) is_passive = true;
            } else {
                if (ci->passive) is_passive = true;
            }
            const char *eff_mode = NULL;
            if (st->address.afi == EIGRP_AFI_IPV6) {
                if (ci->auth_mode_v6[0] && strcasecmp(ci->auth_mode_v6, "none") != 0) {
                    eff_mode = ci->auth_mode_v6;
                } else if (ci->auth_mode[0] && strcasecmp(ci->auth_mode, "none") != 0) {
                    eff_mode = ci->auth_mode;
                }
            } else {
                if (ci->auth_mode_v4[0] && strcasecmp(ci->auth_mode_v4, "none") != 0) {
                    eff_mode = ci->auth_mode_v4;
                } else if (ci->auth_mode[0] && strcasecmp(ci->auth_mode, "none") != 0) {
                    eff_mode = ci->auth_mode;
                }
            }
            if (eff_mode) {
                strncpy(auth_mode, eff_mode, sizeof(auth_mode) - 1);
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_data_lock);
    if (is_passive) {
        return EIGRP_RESULT_SUCCESS;
    }

    srlGoNeighborReport((char *)ni,
                        ip_str,
                        (char *)(st->interface_name ? st->interface_name : ""),
                        (char *)(st->state_name ? st->state_name : "unknown"),
                        st->hold_time,
                        st->uptime_seconds,
                        st->srtt_msec,
                        st->rto_msec,
                        (char *)"disabled",
                        (char *)"normal",
                        auth_mode);
    return EIGRP_RESULT_SUCCESS;
}

void srlShimNeighborsReport(const char *netinst) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    eigrp_instance_t *instances[32];
    int count = 0;
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b && count < 32; b = b->next) {
        if (strcmp(b->netinst, ni) == 0 && b->eigrp) {
            instances[count++] = b->eigrp;
        }
    }

    for (int i = 0; i < count; i++) {
        eigrp_nbr_state_iterate(NULL, instances[i], NULL, false, srl_nbr_iter_cb, (void *)ni);
    }
    pthread_mutex_unlock(&g_data_lock);
}

void srlShimInterfacesReport(const char *netinst) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    typedef struct {
        char ifname[64];
        char ip_str[INET6_ADDRSTRLEN];
        uint32_t prefix_length;
    } rep_intf_t;
    rep_intf_t reports[128];
    int count = 0;

    pthread_mutex_lock(&g_data_lock);
    for (srl_intf_t *ci = g_interfaces; ci && count < 128; ci = ci->next) {
        if (!ci->active && !ci->active_v6) continue;
        if (strcmp(ci->netinst, ni) != 0) continue;
        if (ci->active && ci->address.prefix_length > 0) {
            strncpy(reports[count].ifname, ci->ifname, sizeof(reports[count].ifname) - 1);
            reports[count].ifname[sizeof(reports[count].ifname) - 1] = '\0';
            inet_ntop(AF_INET, ci->address.address.bytes, reports[count].ip_str, sizeof(reports[count].ip_str));
            reports[count].prefix_length = ci->address.prefix_length;
            count++;
        }
        if (ci->active_v6 && ci->address_v6.address.afi == EIGRP_AFI_IPV6 && count < 128) {
            strncpy(reports[count].ifname, ci->ifname, sizeof(reports[count].ifname) - 1);
            reports[count].ifname[sizeof(reports[count].ifname) - 1] = '\0';
            inet_ntop(AF_INET6, ci->address_v6.address.bytes, reports[count].ip_str, sizeof(reports[count].ip_str));
            reports[count].prefix_length = ci->address_v6.prefix_length;
            count++;
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    for (int i = 0; i < count; i++) {
        srlGoInterfaceReport((char *)ni, reports[i].ifname, reports[i].ip_str, reports[i].prefix_length, "Up");
    }
}

int srlShimNeighborClear(const char *netinst, const char *neighbor_ip) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    eigrp_nbr_clear_request_t req;
    memset(&req, 0, sizeof(req));
    eigrp_address_t nbr_addr;
    memset(&nbr_addr, 0, sizeof(nbr_addr));
    bool have_addr = false;

    if (neighbor_ip && strlen(neighbor_ip) > 0 &&
        strcmp(neighbor_ip, "*") != 0 &&
        strcmp(neighbor_ip, "all") != 0) {
        if (inet_pton(AF_INET, neighbor_ip, nbr_addr.bytes) == 1) {
            nbr_addr.afi = EIGRP_AFI_IPV4;
            req.address = &nbr_addr;
            have_addr = true;
        } else if (inet_pton(AF_INET6, neighbor_ip, nbr_addr.bytes) == 1) {
            nbr_addr.afi = EIGRP_AFI_IPV6;
            req.address = &nbr_addr;
            have_addr = true;
        } else {
            return -1;
        }
    }

    eigrp_instance_t *instances[32];
    int count = 0;
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b && count < 32; b = b->next) {
        if (strcmp(b->netinst, ni) == 0 && b->eigrp) {
            instances[count++] = b->eigrp;
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    size_t total_affected = 0;
    for (int i = 0; i < count; i++) {
        eigrp_instance_t *e = instances[i];
        if (have_addr && req.address->afi != eigrp_instance_afi(e)) {
            continue;
        }
        size_t affected = 0;
        (void)eigrp_nbr_clear(e, &req, NULL, NULL, &affected);
        total_affected += affected;
    }
    return (int)total_affected;
}

static eigrp_result_t srl_topo_prefix_cb(const eigrp_topology_prefix_state_t *st, void *arg) {
    const char *ni = (const char *)arg;
    if (!ni) ni = "default";
    if (!st) return EIGRP_RESULT_SUCCESS;
    if (st->successor_count == 0 && !st->active && (st->feasible_distance >= 4294967295ULL || st->feasible_distance == 0)) {
        return EIGRP_RESULT_SUCCESS;
    }
    char pfx_str[64] = "";
    int afi = (st->destination.address.afi == EIGRP_AFI_IPV6) ? AF_INET6 : AF_INET;
    inet_ntop(afi, st->destination.address.bytes, pfx_str, sizeof(pfx_str));
    char pfx_with_len[80];
    snprintf(pfx_with_len, sizeof(pfx_with_len), "%s/%u", pfx_str, st->destination.prefix_length);
    uint8_t rib_scale = srl_get_rib_scale(ni);
    if (rib_scale == 0) rib_scale = 128;
    uint64_t wide_fd = ((uint64_t)st->feasible_distance) * rib_scale;
    srlGoTopologyPrefixReport((char *)ni, pfx_with_len, st->active ? 1 : 0, st->feasible_distance, wide_fd, st->successor_count);
    return EIGRP_RESULT_SUCCESS;
}

static eigrp_result_t srl_topo_route_cb(const eigrp_topology_route_state_t *st, void *arg) {
    const char *ni = (const char *)arg;
    if (!ni) ni = "default";
    if (!st) return EIGRP_RESULT_SUCCESS;
    char nh_str[64] = "";
    int afi = (st->next_hop.afi == EIGRP_AFI_IPV6) ? AF_INET6 : AF_INET;
    inet_ntop(afi, st->next_hop.bytes, nh_str, sizeof(nh_str));
    uint8_t rib_scale = srl_get_rib_scale(ni);
    if (rib_scale == 0) rib_scale = 128;
    uint64_t wide_dist = ((uint64_t)st->distance) * rib_scale;
    uint64_t wide_rd = ((uint64_t)st->reported_distance) * rib_scale;
    srlGoTopologyRouteReport((char *)ni,
                             nh_str,
                             (char *)(st->interface_name ? st->interface_name : ""),
                             st->successor ? 1 : 0,
                             st->feasible_successor ? 1 : 0,
                             st->distance,
                             wide_dist,
                             st->reported_distance,
                             wide_rd);
    return EIGRP_RESULT_SUCCESS;
}

void srlShimTopologyReport(const char *netinst) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    eigrp_instance_t *instances[32];
    int count = 0;
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b && count < 32; b = b->next) {
        if (strcmp(b->netinst, ni) == 0 && b->eigrp) {
            instances[count++] = b->eigrp;
        }
    }

    for (int i = 0; i < count; i++) {
        eigrp_topology_state_iterate(NULL, instances[i], NULL, true, srl_topo_prefix_cb, srl_topo_route_cb, (void *)ni);
    }
    pthread_mutex_unlock(&g_data_lock);
}

static eigrp_result_t srl_intf_traffic_cb(const eigrp_intf_state_t *st, void *arg) {
    const char *ni = (const char *)arg;
    if (!ni) ni = "default";
    if (!st) return EIGRP_RESULT_SUCCESS;
    srlGoTrafficReport((char *)ni,
                       (char *)(st->interface_name ? st->interface_name : ""),
                       st->reliable_multicast_sent,
                       st->unreliable_multicast_sent,
                       st->reliable_unicast_sent,
                       st->unreliable_unicast_sent,
                       st->retransmissions_sent,
                       st->cr_packets_sent);
    return EIGRP_RESULT_SUCCESS;
}

void srlShimTrafficReport(const char *netinst) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    eigrp_instance_t *instances[32];
    int count = 0;
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b && count < 32; b = b->next) {
        if (strcmp(b->netinst, ni) == 0 && b->eigrp) {
            instances[count++] = b->eigrp;
        }
    }

    for (int i = 0; i < count; i++) {
        eigrp_intf_state_iterate(NULL, instances[i], NULL, srl_intf_traffic_cb, (void *)ni);
    }
    pthread_mutex_unlock(&g_data_lock);
}

int srlShimVarianceUpdate(const char *netinst, uint8_t variance) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    eigrp_instance_t *instances[32];
    int count = 0;
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b && count < 32; b = b->next) {
        if (strcmp(b->netinst, ni) == 0 && b->eigrp) {
            instances[count++] = b->eigrp;
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    for (int i = 0; i < count; i++) {
        eigrp_instance_context_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.runtime = instances[i];
        (void)eigrp_metric_variance_update(EIGRP_SET, &ctx, variance);
    }
    return 0;
}

int srlShimMaxPathsUpdate(const char *netinst, uint8_t max_paths) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    eigrp_instance_t *instances[32];
    int count = 0;
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b && count < 32; b = b->next) {
        if (strcmp(b->netinst, ni) == 0 && b->eigrp) {
            instances[count++] = b->eigrp;
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    for (int i = 0; i < count; i++) {
        eigrp_instance_context_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.runtime = instances[i];
        (void)eigrp_topology_maximum_paths_update(EIGRP_SET, &ctx, max_paths);
    }
    return 0;
}

int srlShimMaxHopsUpdate(const char *netinst, uint8_t max_hops) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    eigrp_instance_t *instances[32];
    int count = 0;
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b && count < 32; b = b->next) {
        if (strcmp(b->netinst, ni) == 0 && b->eigrp) {
            instances[count++] = b->eigrp;
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    for (int i = 0; i < count; i++) {
        eigrp_instance_context_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.runtime = instances[i];
        (void)eigrp_metric_maximum_hops_update(EIGRP_SET, &ctx, max_hops);
    }
    return 0;
}

int srlShimActiveTimeUpdate(const char *netinst, uint16_t minutes) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    uint16_t seconds = (minutes == 0) ? 0 : (minutes * 60);
    eigrp_instance_t *instances[32];
    int count = 0;
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b && count < 32; b = b->next) {
        if (strcmp(b->netinst, ni) == 0 && b->eigrp) {
            instances[count++] = b->eigrp;
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    for (int i = 0; i < count; i++) {
        eigrp_instance_context_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.runtime = instances[i];
        ctx.config = eigrp_af_config_runtime_read(instances[i]);
        if (seconds == 0) {
            (void)eigrp_timer_active_time_update(EIGRP_RESET, &ctx, 0);
        } else {
            (void)eigrp_timer_active_time_update(EIGRP_SET, &ctx, seconds);
        }
    }
    return 0;
}

static void srl_intf_metric_update(eigrp_instance_t *runtime, eigrp_intf_t *ei) {
    if (!runtime || !runtime->topology_table || !ei) return;

    eigrp_table_node_t *rn;
    eigrp_prefix_descriptor_t *prefix;
    eigrp_route_descriptor_t *route;
    eigrp_topology_route_iterator_t iterator;

    eigrp_metrics_t metric;
    memset(&metric, 0, sizeof(metric));
    metric.bandwidth = eigrp_bandwidth_to_scaled(ei->params.bandwidth);
    metric.delay = eigrp_delay_to_scaled(ei->params.delay);
    metric.load = ei->params.load;
    metric.reliability = ei->params.reliability;
    metric.mtu[0] = 0xDC;
    metric.mtu[1] = 0x05;
    metric.mtu[2] = 0x00;
    metric.hop_count = 0;

    for (rn = eigrp_table_first(runtime->topology_table); rn; rn = eigrp_table_next(rn)) {
        prefix = rn->info;
        if (!prefix) continue;
        for (route = eigrp_topology_route_iterator_first(prefix, &iterator); route;
             route = eigrp_topology_route_iterator_next(&iterator)) {
            if (route->ei == ei && route->adv_router == runtime->neighbor_self) {
                route->metric = metric;
                route->reported_metric = metric;
                route->total_metric = metric;
                route->distance = eigrp_metric_calculate(runtime, metric);
                route->reported_distance = 0;
            }
        }
    }

    eigrp_topology_metric_update(runtime);

    for (rn = eigrp_table_first(runtime->topology_table); rn; rn = eigrp_table_next(rn)) {
        prefix = rn->info;
        if (!prefix) continue;
        bool has_conn = false;
        for (route = eigrp_topology_route_iterator_first(prefix, &iterator); route;
             route = eigrp_topology_route_iterator_next(&iterator)) {
            if (route->adv_router == runtime->neighbor_self && route->ei) {
                eigrp_metrics_t m;
                memset(&m, 0, sizeof(m));
                m.bandwidth = eigrp_bandwidth_to_scaled(route->ei->params.bandwidth);
                m.delay = eigrp_delay_to_scaled(route->ei->params.delay);
                m.load = route->ei->params.load;
                m.reliability = route->ei->params.reliability;
                m.mtu[0] = 0xDC;
                m.mtu[1] = 0x05;
                m.mtu[2] = 0x00;
                m.hop_count = 0;
                route->metric = m;
                route->reported_metric = m;
                route->total_metric = m;
                route->distance = eigrp_metric_calculate(runtime, m);
                route->reported_distance = 0;
                has_conn = true;
            }
        }
        if (has_conn) {
            eigrp_route_descriptor_t *best = eigrp_topology_route_read(prefix);
            if (best && best->adv_router == runtime->neighbor_self) {
                prefix->distance = best->distance;
                prefix->fdistance = best->distance;
                prefix->rdistance = 0;
                prefix->reported_metric = best->reported_metric;
                eigrp_update_routing_table(runtime, prefix);
                prefix->req_action |= EIGRP_FSM_NEED_UPDATE;
                if (!eigrp_list_lookup(runtime->topology_changes, prefix)) {
                    eigrp_list_add(runtime->topology_changes, prefix);
                }
            }
        }
    }
    eigrp_update_send_all(runtime, NULL);
}

int srlShimInterfaceEnable(const char *netinst, const char *ifname, bool passive, uint16_t hello_interval, uint16_t hold_time, bool admin_up, bool split_horizon, bool next_hop_self, uint32_t bandwidth, uint32_t delay) {
    if (!ifname || !ifname[0]) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    srlShimInterfacesScan(ni);

    eigrp_instance_t *runtime = srl_instance_get_afi(ni, EIGRP_AFI_IPV4);
    if (!runtime) return -1;

    pthread_mutex_lock(&g_data_lock);
    srl_intf_t *found = NULL;
    for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
        if (strcmp(ci->netinst, ni) == 0 && srl_match_ifname(ci->ifname, ifname)) {
            found = ci;
            break;
        }
    }
    if (!found) {
        for (int retry = 0; retry < 3 && !found; retry++) {
            pthread_mutex_unlock(&g_data_lock);
            usleep(20000);
            srlShimInterfacesScan(ni);
            pthread_mutex_lock(&g_data_lock);
            for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
                if (strcmp(ci->netinst, ni) == 0 && srl_match_ifname(ci->ifname, ifname)) {
                    found = ci;
                    break;
                }
            }
        }
    }
    if (!found) {
        pthread_mutex_unlock(&g_data_lock);
        return -1;
    }

    found->active = admin_up;
    found->passive = passive;
    if (bandwidth > 0) {
        found->bandwidth = bandwidth;
    } else {
        found->bandwidth = EIGRP_BANDWIDTH_DEFAULT;
    }

    eigrp_prefix_t pfx;
    memset(&pfx, 0, sizeof(pfx));
    pfx.address.afi = EIGRP_AFI_IPV4;
    pfx.prefix_length = found->address.prefix_length;

    uint32_t ip = 0;
    memcpy(&ip, found->address.address.bytes, 4);
    uint32_t mask = (pfx.prefix_length == 0) ? 0 : htonl(~((1ULL << (32 - pfx.prefix_length)) - 1));
    uint32_t net_ip = ip & mask;
    memcpy(pfx.address.bytes, &net_ip, 4);
    char actual_ifname[64];
    strncpy(actual_ifname, found->ifname, sizeof(actual_ifname) - 1);
    actual_ifname[sizeof(actual_ifname) - 1] = '\0';
    eigrp_ifindex_t ifidx = found->ifindex;
    eigrp_prefix_t intf_addr = found->address;
    uint32_t intf_bw = found->bandwidth;
    uint32_t intf_mtu = found->mtu;

    char eff_mode[32] = {0};
    char eff_key[256] = {0};
    char eff_kc[64] = {0};
    const char *m = (found->auth_mode_v4[0]) ? found->auth_mode_v4 : found->auth_mode;
    const char *k = (found->auth_key_v4[0]) ? found->auth_key_v4 : found->auth_key;
    const char *kc = (found->keychain_v4[0]) ? found->keychain_v4 : found->keychain;
    if (m && m[0]) strncpy(eff_mode, m, sizeof(eff_mode) - 1);
    if (k && k[0]) strncpy(eff_key, k, sizeof(eff_key) - 1);
    if (kc && kc[0]) strncpy(eff_kc, kc, sizeof(eff_kc) - 1);

    pthread_mutex_unlock(&g_data_lock);

    eigrp_instance_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.runtime = runtime;

    if (admin_up) {
        eigrp_network_create(&ctx, &pfx);

        eigrp_intf_t *ei = eigrp_intf_lookup_by_name(runtime, actual_ifname);
        if (!ei) {
            ei = eigrp_intf_lookup_by_ifindex(runtime, ifidx);
        }
        if (!ei && admin_up && intf_addr.prefix_length > 0) {
            eigrp_intf_runtime_state_t st;
            memset(&st, 0, sizeof(st));
            st.interface_name = actual_ifname;
            st.ifindex = ifidx;
            st.address = intf_addr;
            st.type = 1;
            st.secondary = false;
            st.operative = true;
            st.bandwidth = (bandwidth > 0) ? bandwidth : intf_bw;
            st.mtu = intf_mtu;
            eigrp_intf_runtime_update(EIGRP_SET, runtime, &st, NULL);
            ei = eigrp_intf_lookup_by_name(runtime, actual_ifname);
            if (!ei) {
                ei = eigrp_intf_lookup_by_ifindex(runtime, ifidx);
            }
        }
        if (ei) {
            bool was_passive = (ei->params.passive_interface == EIGRP_INTF_PASSIVE);
            ei->params.passive_interface = passive ? EIGRP_INTF_PASSIVE : EIGRP_INTF_ACTIVE;
            ei->split_horizon = split_horizon;
            ei->next_hop_self = next_hop_self;
            bool metric_changed = false;
            if (bandwidth > 0 && bandwidth != ei->params.bandwidth) {
                ei->params.bandwidth = bandwidth;
                ei->curr_bandwidth = bandwidth;
                metric_changed = true;
            } else if (bandwidth == 0 && ei->params.bandwidth != EIGRP_BANDWIDTH_DEFAULT) {
                ei->params.bandwidth = EIGRP_BANDWIDTH_DEFAULT;
                ei->curr_bandwidth = EIGRP_BANDWIDTH_DEFAULT;
                metric_changed = true;
            }
            if (delay > 0 && delay != ei->params.delay) {
                ei->params.delay = delay;
                metric_changed = true;
            } else if (delay == 0 && ei->params.delay != EIGRP_DELAY_DEFAULT) {
                ei->params.delay = EIGRP_DELAY_DEFAULT;
                metric_changed = true;
            }
            if (metric_changed) {
                srl_intf_metric_update(runtime, ei);
            }
            eigrp_intf_multicast_update(EIGRP_SET, ei);
            if (passive) {
                if (!strstr(actual_ifname, "system") && !strstr(actual_ifname, "lo")) {
                    if (!was_passive) {
                        eigrp_hello_send(ei, EIGRP_HELLO_GRACEFUL_SHUTDOWN, NULL);
                    }
                    eigrp_nbr_clear_request_t req;
                    memset(&req, 0, sizeof(req));
                    req.interface_name = (ei->name && ei->name[0]) ? ei->name : actual_ifname;
                    size_t affected = 0;
                    (void)eigrp_nbr_clear(runtime, &req, NULL, NULL, &affected);
                    if (ei->nbrs) {
                        eigrp_list_item_t *nbr_node = NULL, *next_node = NULL;
                        eigrp_nbr_t *nbr = NULL;
                        for (EIGRP_LIST_ITERATE(ei->nbrs, nbr_node, next_node, nbr)) {
                            if (nbr) {
                                eigrp_nbr_delete(nbr);
                            }
                        }
                    }
                }
            } else if (was_passive && !strstr(actual_ifname, "system") && !strstr(actual_ifname, "lo")) {
                eigrp_hello_send(ei, EIGRP_HELLO_NORMAL, NULL);
            }
            if (hello_interval > 0) {
                ei->params.v_hello = hello_interval;
            }
            if (hold_time > 0) {
                ei->params.v_wait = hold_time;
            }
            if (eff_mode[0] && strcasecmp(eff_mode, "none") != 0) {
                ei->params.auth_type = (strcasecmp(eff_mode, "md5") == 0) ? EIGRP_AUTH_TYPE_MD5 : EIGRP_AUTH_TYPE_SHA256;
                if (eff_key[0]) {
                    if (ei->params.auth_password) free(ei->params.auth_password);
                    ei->params.auth_password = strdup(eff_key);
                }
                if (eff_kc[0]) {
                    if (ei->params.auth_keychain) free(ei->params.auth_keychain);
                    ei->params.auth_keychain = strdup(eff_kc);
                }
            } else {
                ei->params.auth_type = EIGRP_AUTH_TYPE_NONE;
                if (ei->params.auth_password) {
                    free(ei->params.auth_password);
                    ei->params.auth_password = NULL;
                }
                if (ei->params.auth_keychain) {
                    free(ei->params.auth_keychain);
                    ei->params.auth_keychain = NULL;
                }
            }
            if (!ei->operative && !passive) {
                eigrp_intf_up(runtime, ei);
            }
        }
    } else {
        eigrp_network_delete(&ctx, &pfx);
        eigrp_intf_t *ei = eigrp_intf_lookup_by_name(runtime, actual_ifname);
        if (!ei) {
            ei = eigrp_intf_lookup_by_ifindex(runtime, ifidx);
        }
        if (ei) {
            if (!strstr(actual_ifname, "system") && !strstr(actual_ifname, "lo")) {
                eigrp_hello_send(ei, EIGRP_HELLO_GRACEFUL_SHUTDOWN, NULL);
                eigrp_nbr_clear_request_t req;
                memset(&req, 0, sizeof(req));
                req.interface_name = (ei->name && ei->name[0]) ? ei->name : actual_ifname;
                size_t affected = 0;
                (void)eigrp_nbr_clear(runtime, &req, NULL, NULL, &affected);
                if (ei->nbrs) {
                    eigrp_list_item_t *nbr_node = NULL, *next_node = NULL;
                    eigrp_nbr_t *nbr = NULL;
                    for (EIGRP_LIST_ITERATE(ei->nbrs, nbr_node, next_node, nbr)) {
                        if (nbr) {
                            eigrp_nbr_delete(nbr);
                        }
                    }
                }
            }
            eigrp_intf_down(ei);
        }
    }

    return 0;
}

int srlShimInterfaceDisable(const char *netinst, const char *ifname) {
    return srlShimInterfaceEnable(netinst, ifname, false, 0, 0, false, true, false, 0, 0);
}

int srlShimInterfaceEnableV6(const char *netinst, const char *ifname, bool passive, uint16_t hello_interval, uint16_t hold_time, bool admin_up, bool split_horizon, bool next_hop_self, uint32_t bandwidth, uint32_t delay) {
    if (!ifname || !ifname[0]) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    srlShimInterfacesScan(ni);

    eigrp_instance_t *runtime_v6 = srl_instance_get_afi(ni, EIGRP_AFI_IPV6);
    if (!runtime_v6) return -1;

    pthread_mutex_lock(&g_data_lock);
    srl_intf_t *found = NULL;
    for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
        if (strcmp(ci->netinst, ni) == 0 && srl_match_ifname(ci->ifname, ifname)) {
            found = ci;
            break;
        }
    }
    if (!found) {
        for (int retry = 0; retry < 3 && !found; retry++) {
            pthread_mutex_unlock(&g_data_lock);
            usleep(20000);
            srlShimInterfacesScan(ni);
            pthread_mutex_lock(&g_data_lock);
            for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
                if (strcmp(ci->netinst, ni) == 0 && srl_match_ifname(ci->ifname, ifname)) {
                    found = ci;
                    break;
                }
            }
        }
    }
    if (!found) {
        pthread_mutex_unlock(&g_data_lock);
        return -1;
    }

    found->active_v6 = admin_up;
    found->passive_v6 = passive;
    if (bandwidth > 0) {
        found->bandwidth = bandwidth;
    } else {
        found->bandwidth = EIGRP_BANDWIDTH_DEFAULT;
    }

    char actual_ifname[64];
    strncpy(actual_ifname, found->ifname, sizeof(actual_ifname) - 1);
    actual_ifname[sizeof(actual_ifname) - 1] = '\0';
    eigrp_ifindex_t ifidx = found->ifindex;

    eigrp_prefix_t addr_v6 = found->address_v6;
    if (addr_v6.address.afi != EIGRP_AFI_IPV6 && found->global_v6.address.afi == EIGRP_AFI_IPV6) {
        addr_v6 = found->global_v6;
    }
    bool has_v6 = (addr_v6.address.afi == EIGRP_AFI_IPV6);
    eigrp_prefix_t glob_v6 = found->global_v6;
    bool has_glob_v6 = (glob_v6.address.afi == EIGRP_AFI_IPV6 && glob_v6.prefix_length > 0);
    uint32_t intf_bw = found->bandwidth;
    uint32_t intf_mtu = found->mtu;

    char eff_mode[32] = {0};
    char eff_key[128] = {0};
    char eff_kc[64] = {0};
    const char *m = (found->auth_mode_v6[0]) ? found->auth_mode_v6 : found->auth_mode;
    const char *k = (found->auth_key_v6[0]) ? found->auth_key_v6 : found->auth_key;
    const char *kc = (found->keychain_v6[0]) ? found->keychain_v6 : found->keychain;
    if (m && m[0]) strncpy(eff_mode, m, sizeof(eff_mode) - 1);
    if (k && k[0]) strncpy(eff_key, k, sizeof(eff_key) - 1);
    if (kc && kc[0]) strncpy(eff_kc, kc, sizeof(eff_kc) - 1);

    pthread_mutex_unlock(&g_data_lock);

    if (has_v6) {
        eigrp_intf_t *ei6 = eigrp_intf_lookup_by_name(runtime_v6, actual_ifname);
        if (!ei6) {
            ei6 = eigrp_intf_lookup_by_ifindex(runtime_v6, ifidx);
        }
        if (!ei6 && admin_up) {
            eigrp_intf_runtime_state_t st6;
            memset(&st6, 0, sizeof(st6));
            st6.interface_name = actual_ifname;
            st6.ifindex = ifidx;
            st6.address = addr_v6;
            st6.type = 1;
            st6.secondary = false;
            st6.operative = true;
            st6.bandwidth = intf_bw;
            st6.mtu = intf_mtu;
            eigrp_intf_runtime_update(EIGRP_SET, runtime_v6, &st6, NULL);
            ei6 = eigrp_intf_lookup_by_name(runtime_v6, actual_ifname);
        }
        if (ei6) {
            bool was_passive = (ei6->params.passive_interface == EIGRP_INTF_PASSIVE);
            ei6->params.passive_interface = passive ? EIGRP_INTF_PASSIVE : EIGRP_INTF_ACTIVE;
            ei6->split_horizon = split_horizon;
            ei6->next_hop_self = next_hop_self;
            bool metric_changed = false;
            if (bandwidth > 0 && bandwidth != ei6->params.bandwidth) {
                ei6->params.bandwidth = bandwidth;
                ei6->curr_bandwidth = bandwidth;
                metric_changed = true;
            } else if (bandwidth == 0 && ei6->params.bandwidth != EIGRP_BANDWIDTH_DEFAULT) {
                ei6->params.bandwidth = EIGRP_BANDWIDTH_DEFAULT;
                ei6->curr_bandwidth = EIGRP_BANDWIDTH_DEFAULT;
                metric_changed = true;
            }
            if (delay > 0 && delay != ei6->params.delay) {
                ei6->params.delay = delay;
                metric_changed = true;
            } else if (delay == 0 && ei6->params.delay != EIGRP_DELAY_DEFAULT) {
                ei6->params.delay = EIGRP_DELAY_DEFAULT;
                metric_changed = true;
            }
            if (metric_changed) {
                srl_intf_metric_update(runtime_v6, ei6);
            }
            eigrp_intf_multicast_update(EIGRP_SET, ei6);
            if (passive) {
                if (!strstr(actual_ifname, "system") && !strstr(actual_ifname, "lo")) {
                    if (!was_passive) {
                        eigrp_hello_send(ei6, EIGRP_HELLO_GRACEFUL_SHUTDOWN, NULL);
                    }
                    eigrp_nbr_clear_request_t req;
                    memset(&req, 0, sizeof(req));
                    req.interface_name = (ei6->name && ei6->name[0]) ? ei6->name : actual_ifname;
                    size_t affected = 0;
                    (void)eigrp_nbr_clear(runtime_v6, &req, NULL, NULL, &affected);
                    if (ei6->nbrs) {
                        eigrp_list_item_t *nbr_node = NULL, *next_node = NULL;
                        eigrp_nbr_t *nbr = NULL;
                        for (EIGRP_LIST_ITERATE(ei6->nbrs, nbr_node, next_node, nbr)) {
                            if (nbr) {
                                eigrp_nbr_delete(nbr);
                            }
                        }
                    }
                }
            } else if (was_passive && !strstr(actual_ifname, "system") && !strstr(actual_ifname, "lo")) {
                eigrp_hello_send(ei6, EIGRP_HELLO_NORMAL, NULL);
            }
            if (hello_interval > 0) {
                ei6->params.v_hello = hello_interval;
            }
            if (hold_time > 0) {
                ei6->params.v_wait = hold_time;
            }
            if (eff_mode[0] && strcasecmp(eff_mode, "none") != 0) {
                ei6->params.auth_type = (strcasecmp(eff_mode, "md5") == 0) ? EIGRP_AUTH_TYPE_MD5 : EIGRP_AUTH_TYPE_SHA256;
                if (eff_key[0]) {
                    if (ei6->params.auth_password) free(ei6->params.auth_password);
                    ei6->params.auth_password = strdup(eff_key);
                }
                if (eff_kc[0]) {
                    if (ei6->params.auth_keychain) free(ei6->params.auth_keychain);
                    ei6->params.auth_keychain = strdup(eff_kc);
                }
            } else {
                ei6->params.auth_type = EIGRP_AUTH_TYPE_NONE;
                if (ei6->params.auth_password) {
                    free(ei6->params.auth_password);
                    ei6->params.auth_password = NULL;
                }
                if (ei6->params.auth_keychain) {
                    free(ei6->params.auth_keychain);
                    ei6->params.auth_keychain = NULL;
                }
            }
            if (!ei6->operative && !passive && admin_up) {
                eigrp_intf_up(runtime_v6, ei6);
            } else if (!admin_up) {
                if (!strstr(actual_ifname, "system") && !strstr(actual_ifname, "lo")) {
                    eigrp_hello_send(ei6, EIGRP_HELLO_GRACEFUL_SHUTDOWN, NULL);
                    eigrp_nbr_clear_request_t req;
                    memset(&req, 0, sizeof(req));
                    req.interface_name = (ei6->name && ei6->name[0]) ? ei6->name : actual_ifname;
                    size_t affected = 0;
                    (void)eigrp_nbr_clear(runtime_v6, &req, NULL, NULL, &affected);
                    if (ei6->nbrs) {
                        eigrp_list_item_t *nbr_node = NULL, *next_node = NULL;
                        eigrp_nbr_t *nbr = NULL;
                        for (EIGRP_LIST_ITERATE(ei6->nbrs, nbr_node, next_node, nbr)) {
                            if (nbr) {
                                eigrp_nbr_delete(nbr);
                            }
                        }
                    }
                }
                eigrp_intf_down(ei6);
            }
        }
        if (admin_up && has_glob_v6) {
            char pfx_str[128];
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, glob_v6.address.bytes, ip_str, sizeof(ip_str));
            snprintf(pfx_str, sizeof(pfx_str), "%s/%u", ip_str, glob_v6.prefix_length);
            srlShimRouteOriginateV6(ni, pfx_str, NULL);
        } else if (!admin_up && has_glob_v6) {
            char pfx_str[128];
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, glob_v6.address.bytes, ip_str, sizeof(ip_str));
            snprintf(pfx_str, sizeof(pfx_str), "%s/%u", ip_str, glob_v6.prefix_length);
            srlShimRouteWithdrawV6(ni, pfx_str);
        }
    } else {
        eigrp_intf_t *ei6 = eigrp_intf_lookup_by_name(runtime_v6, actual_ifname);
        if (!ei6) {
            ei6 = eigrp_intf_lookup_by_ifindex(runtime_v6, ifidx);
        }
        if (ei6) {
            if (!strstr(actual_ifname, "system") && !strstr(actual_ifname, "lo")) {
                eigrp_hello_send(ei6, EIGRP_HELLO_GRACEFUL_SHUTDOWN, NULL);
                eigrp_nbr_clear_request_t req;
                memset(&req, 0, sizeof(req));
                req.interface_name = (ei6->name && ei6->name[0]) ? ei6->name : actual_ifname;
                size_t affected = 0;
                (void)eigrp_nbr_clear(runtime_v6, &req, NULL, NULL, &affected);
                if (ei6->nbrs) {
                    eigrp_list_item_t *nbr_node = NULL, *next_node = NULL;
                    eigrp_nbr_t *nbr = NULL;
                    for (EIGRP_LIST_ITERATE(ei6->nbrs, nbr_node, next_node, nbr)) {
                        if (nbr) {
                            eigrp_nbr_delete(nbr);
                        }
                    }
                }
            }
            eigrp_intf_down(ei6);
        }
    }

    return 0;
}

int srlShimInterfaceDisableV6(const char *netinst, const char *ifname) {
    return srlShimInterfaceEnableV6(netinst, ifname, false, 0, 0, false, true, false, 0, 0);
}

int srlShimInstanceDeleteV6(const char *netinst, uint16_t asn) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    pthread_mutex_lock(&g_data_lock);
    g_pending_netinst[0] = '\0';
    for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
        if (strcmp(ci->netinst, ni) == 0) {
            ci->active_v6 = false;
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    char inst_name[128];
    snprintf(inst_name, sizeof(inst_name), "srl-v6-%s-%u", ni, asn);
    eigrp_af_config_delete(inst_name, EIGRP_AFI_IPV6, ni, asn);

    eigrp_instance_t *runtime_v6 = srl_instance_get_afi(ni, EIGRP_AFI_IPV6);
    if (runtime_v6) {
        eigrp_instance_delete(runtime_v6);
    }
    return 0;
}

int srlShimRedistributeUpdate(const char *netinst, const char *policy_name, uint32_t bw, uint32_t delay, uint8_t reliability, uint8_t load, uint32_t mtu) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    eigrp_metric_values_t metric;
    memset(&metric, 0, sizeof(metric));
    metric.bandwidth = (bw > 0) ? bw : 100000;
    metric.delay = (delay > 0) ? delay : 100;
    metric.reliability = (reliability > 0) ? reliability : 255;
    metric.load = (load > 0) ? load : 1;
    metric.mtu = (mtu > 0) ? mtu : 1500;

    eigrp_redist_source_t src_conn = { .protocol = EIGRP_REDISTRIBUTE_PROTOCOL_CONNECTED, .route_instance = 0 };
    eigrp_redist_source_t src_stat = { .protocol = EIGRP_REDISTRIBUTE_PROTOCOL_STATIC, .route_instance = 0 };
    eigrp_redist_source_t src_bgp  = { .protocol = EIGRP_REDISTRIBUTE_PROTOCOL_BGP, .route_instance = 0 };
    eigrp_redist_source_t src_ospf = { .protocol = EIGRP_REDISTRIBUTE_PROTOCOL_OSPF, .route_instance = 0 };
    eigrp_redist_source_t src_isis = { .protocol = EIGRP_REDISTRIBUTE_PROTOCOL_ISIS, .route_instance = 0 };

    eigrp_instance_t *instances[32];
    int count = 0;
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b && count < 32; b = b->next) {
        if (strcmp(b->netinst, ni) == 0 && b->eigrp) {
            instances[count++] = b->eigrp;
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    for (int i = 0; i < count; i++) {
        eigrp_instance_context_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.runtime = instances[i];

        if (policy_name && policy_name[0]) {
            eigrp_redist_add(&ctx, &src_conn, &metric, policy_name);
            eigrp_redist_add(&ctx, &src_stat, &metric, policy_name);
            eigrp_redist_add(&ctx, &src_bgp, &metric, policy_name);
            eigrp_redist_add(&ctx, &src_ospf, &metric, policy_name);
            eigrp_redist_add(&ctx, &src_isis, &metric, policy_name);
        } else {
            eigrp_redist_remove(&ctx, &src_conn);
            eigrp_redist_remove(&ctx, &src_stat);
            eigrp_redist_remove(&ctx, &src_bgp);
            eigrp_redist_remove(&ctx, &src_ospf);
            eigrp_redist_remove(&ctx, &src_isis);
        }
    }
    return 0;
}

int srlShimRouteOriginateV6(const char *netinst, const char *prefix_str, const char *nexthop_str) {
    if (!prefix_str || !prefix_str[0]) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    eigrp_instance_t *runtime = srl_instance_get_afi(ni, EIGRP_AFI_IPV6);
    if (!runtime) return -1;

    char pfx_copy[128];
    strncpy(pfx_copy, prefix_str, sizeof(pfx_copy) - 1);
    pfx_copy[sizeof(pfx_copy) - 1] = '\0';

    char *slash = strchr(pfx_copy, '/');
    uint8_t plen = 128;
    if (slash) {
        *slash = '\0';
        plen = (uint8_t)atoi(slash + 1);
    }

    eigrp_prefix_t pfx;
    memset(&pfx, 0, sizeof(pfx));
    pfx.address.afi = EIGRP_AFI_IPV6;
    if (inet_pton(AF_INET6, pfx_copy, pfx.address.bytes) != 1) {
        return -1;
    }
    pfx.prefix_length = plen;
    eigrp_prefix_normalize(&pfx);

    eigrp_rib_route_t sr;
    memset(&sr, 0, sizeof(sr));
    sr.prefix = pfx;
    sr.redist.source.protocol = EIGRP_REDISTRIBUTE_PROTOCOL_CONNECTED;
    sr.install.type = EIGRP_RIB_ROUTE_INTERNAL;

    eigrp_rib_nexthop_t nh;
    memset(&nh, 0, sizeof(nh));
    if (nexthop_str && nexthop_str[0] && strcmp(nexthop_str, "::") != 0) {
        nh.gateway_present = true;
        nh.gateway.afi = EIGRP_AFI_IPV6;
        if (inet_pton(AF_INET6, nexthop_str, nh.gateway.bytes) == 1) {
            sr.nexthops = &nh;
            sr.nexthop_count = 1;
        }
    }

    eigrp_metrics_t metric;
    memset(&metric, 0, sizeof(metric));
    metric.bandwidth = 1000000;
    metric.delay = 100;
    metric.reliability = 255;
    metric.mtu[0] = 0;
    metric.mtu[1] = 5;
    metric.mtu[2] = 0xdc;
    metric.hop_count = 0;

    eigrp_result_t res = eigrp_topology_redistributed_route_update(runtime, &sr, &metric);
    return (res == EIGRP_RESULT_SUCCESS) ? 0 : -1;
}

int srlShimRouteWithdrawV6(const char *netinst, const char *prefix_str) {
    if (!prefix_str || !prefix_str[0]) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    eigrp_instance_t *runtime = srl_instance_get_afi(ni, EIGRP_AFI_IPV6);
    if (!runtime) return -1;

    char pfx_copy[128];
    strncpy(pfx_copy, prefix_str, sizeof(pfx_copy) - 1);
    pfx_copy[sizeof(pfx_copy) - 1] = '\0';

    char *slash = strchr(pfx_copy, '/');
    uint8_t plen = 128;
    if (slash) {
        *slash = '\0';
        plen = (uint8_t)atoi(slash + 1);
    }

    eigrp_prefix_t pfx;
    memset(&pfx, 0, sizeof(pfx));
    pfx.address.afi = EIGRP_AFI_IPV6;
    if (inet_pton(AF_INET6, pfx_copy, pfx.address.bytes) != 1) {
        return -1;
    }
    pfx.prefix_length = plen;
    eigrp_prefix_normalize(&pfx);

    eigrp_rib_route_t sr;
    memset(&sr, 0, sizeof(sr));
    sr.prefix = pfx;
    sr.redist.source.protocol = EIGRP_REDISTRIBUTE_PROTOCOL_CONNECTED;
    sr.install.type = EIGRP_RIB_ROUTE_INTERNAL;

    eigrp_result_t res = eigrp_topology_redistributed_route_remove(runtime, &sr);
    return (res == EIGRP_RESULT_SUCCESS) ? 0 : -1;
}

int srlShimRouteRedistributeAdd(const char *netinst, const char *prefix_str, const char *proto_str,
                                const char *nexthop_str, uint32_t bw, uint32_t delay,
                                uint8_t reliability, uint8_t load, uint32_t mtu) {
    if (!prefix_str || !prefix_str[0]) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    bool is_v6 = (strchr(prefix_str, ':') != NULL);
    int afi = is_v6 ? EIGRP_AFI_IPV6 : EIGRP_AFI_IPV4;
    eigrp_instance_t *runtime = srl_instance_get_afi(ni, afi);
    if (!runtime) return -1;

    char pfx_copy[128];
    strncpy(pfx_copy, prefix_str, sizeof(pfx_copy) - 1);
    pfx_copy[sizeof(pfx_copy) - 1] = '\0';

    char *slash = strchr(pfx_copy, '/');
    uint8_t plen = is_v6 ? 128 : 32;
    if (slash) {
        *slash = '\0';
        plen = (uint8_t)atoi(slash + 1);
    }

    eigrp_prefix_t pfx;
    memset(&pfx, 0, sizeof(pfx));
    pfx.address.afi = afi;
    int af_family = is_v6 ? AF_INET6 : AF_INET;
    if (inet_pton(af_family, pfx_copy, pfx.address.bytes) != 1) {
        return -1;
    }
    pfx.prefix_length = plen;
    eigrp_prefix_normalize(&pfx);

    eigrp_redist_protocol_t protocol = EIGRP_REDISTRIBUTE_PROTOCOL_STATIC;
    if (proto_str) {
        if (strcasestr(proto_str, "ospf") != NULL) {
            protocol = EIGRP_REDISTRIBUTE_PROTOCOL_OSPF;
        } else if (strcasestr(proto_str, "bgp") != NULL) {
            protocol = EIGRP_REDISTRIBUTE_PROTOCOL_BGP;
        } else if (strcasestr(proto_str, "isis") != NULL || strcasestr(proto_str, "is-is") != NULL) {
            protocol = EIGRP_REDISTRIBUTE_PROTOCOL_ISIS;
        } else if (strcasestr(proto_str, "connected") != NULL || strcasestr(proto_str, "local") != NULL || strcasestr(proto_str, "host") != NULL) {
            protocol = EIGRP_REDISTRIBUTE_PROTOCOL_CONNECTED;
        } else if (strcasestr(proto_str, "static") != NULL) {
            protocol = EIGRP_REDISTRIBUTE_PROTOCOL_STATIC;
        }
    }

    eigrp_rib_route_t sr;
    memset(&sr, 0, sizeof(sr));
    sr.prefix = pfx;
    sr.redist.source.protocol = protocol;
    sr.redist.source.route_instance = 0;
    sr.install.type = EIGRP_RIB_ROUTE_EXTERNAL;

    eigrp_rib_nexthop_t nh;
    memset(&nh, 0, sizeof(nh));
    if (nexthop_str && nexthop_str[0] && strcmp(nexthop_str, "::") != 0 && strcmp(nexthop_str, "0.0.0.0") != 0) {
        nh.gateway_present = true;
        nh.gateway.afi = afi;
        if (inet_pton(af_family, nexthop_str, nh.gateway.bytes) == 1) {
            sr.nexthops = &nh;
            sr.nexthop_count = 1;
        }
    }

    eigrp_metrics_t metric;
    memset(&metric, 0, sizeof(metric));
    metric.bandwidth = eigrp_bandwidth_to_scaled((bw > 0) ? bw : 100000);
    metric.delay = (delay > 0) ? delay : 100;
    metric.reliability = (reliability > 0) ? reliability : 255;
    metric.load = (load > 0) ? load : 1;
    uint32_t m = (mtu > 0) ? mtu : 1500;
    metric.mtu[0] = m & 0xff;
    metric.mtu[1] = (m >> 8) & 0xff;
    metric.mtu[2] = (m >> 16) & 0xff;
    metric.hop_count = 0;

    eigrp_result_t res = eigrp_topology_redistributed_route_update(runtime, &sr, &metric);
    return (res == EIGRP_RESULT_SUCCESS) ? 0 : -1;
}

int srlShimRouteRedistributeRemove(const char *netinst, const char *prefix_str, const char *proto_str) {
    if (!prefix_str || !prefix_str[0]) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    bool is_v6 = (strchr(prefix_str, ':') != NULL);
    int afi = is_v6 ? EIGRP_AFI_IPV6 : EIGRP_AFI_IPV4;
    eigrp_instance_t *runtime = srl_instance_get_afi(ni, afi);
    if (!runtime) return -1;

    char pfx_copy[128];
    strncpy(pfx_copy, prefix_str, sizeof(pfx_copy) - 1);
    pfx_copy[sizeof(pfx_copy) - 1] = '\0';

    char *slash = strchr(pfx_copy, '/');
    uint8_t plen = is_v6 ? 128 : 32;
    if (slash) {
        *slash = '\0';
        plen = (uint8_t)atoi(slash + 1);
    }

    eigrp_prefix_t pfx;
    memset(&pfx, 0, sizeof(pfx));
    pfx.address.afi = afi;
    int af_family = is_v6 ? AF_INET6 : AF_INET;
    if (inet_pton(af_family, pfx_copy, pfx.address.bytes) != 1) {
        return -1;
    }
    pfx.prefix_length = plen;
    eigrp_prefix_normalize(&pfx);

    eigrp_redist_protocol_t protos[] = {
        EIGRP_REDISTRIBUTE_PROTOCOL_OSPF,
        EIGRP_REDISTRIBUTE_PROTOCOL_BGP,
        EIGRP_REDISTRIBUTE_PROTOCOL_ISIS,
        EIGRP_REDISTRIBUTE_PROTOCOL_STATIC,
        EIGRP_REDISTRIBUTE_PROTOCOL_CONNECTED
    };
    int nprotos = sizeof(protos) / sizeof(protos[0]);

    if (proto_str && proto_str[0]) {
        if (strcasestr(proto_str, "ospf") != NULL) {
            protos[0] = EIGRP_REDISTRIBUTE_PROTOCOL_OSPF;
            nprotos = 1;
        } else if (strcasestr(proto_str, "bgp") != NULL) {
            protos[0] = EIGRP_REDISTRIBUTE_PROTOCOL_BGP;
            nprotos = 1;
        } else if (strcasestr(proto_str, "isis") != NULL || strcasestr(proto_str, "is-is") != NULL) {
            protos[0] = EIGRP_REDISTRIBUTE_PROTOCOL_ISIS;
            nprotos = 1;
        } else if (strcasestr(proto_str, "static") != NULL) {
            protos[0] = EIGRP_REDISTRIBUTE_PROTOCOL_STATIC;
            nprotos = 1;
        } else if (strcasestr(proto_str, "connected") != NULL || strcasestr(proto_str, "local") != NULL || strcasestr(proto_str, "host") != NULL) {
            protos[0] = EIGRP_REDISTRIBUTE_PROTOCOL_CONNECTED;
            nprotos = 1;
        }
    }

    int success = 0;
    for (int i = 0; i < nprotos; i++) {
        eigrp_rib_route_t sr;
        memset(&sr, 0, sizeof(sr));
        sr.prefix = pfx;
        sr.redist.source.protocol = protos[i];
        sr.redist.source.route_instance = 0;
        sr.install.type = EIGRP_RIB_ROUTE_EXTERNAL;
        if (eigrp_topology_redistributed_route_remove(runtime, &sr) == EIGRP_RESULT_SUCCESS) {
            success = 1;
        }
    }
    return success ? 0 : -1;
}

int srlShimInstanceCreateV6(const char *netinst, uint16_t asn, const char *router_id) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    pthread_mutex_lock(&g_data_lock);
    strncpy(g_pending_netinst, ni, sizeof(g_pending_netinst) - 1);
    g_pending_netinst[sizeof(g_pending_netinst) - 1] = '\0';
    pthread_mutex_unlock(&g_data_lock);

    char inst_name[128];
    snprintf(inst_name, sizeof(inst_name), "srl-v6-%s-%u", ni, asn);

    eigrp_af_config_t *existing_af = eigrp_af_config_read(inst_name, EIGRP_AFI_IPV6, ni, asn);
    if (existing_af && existing_af->runtime) {
        eigrp_instance_start(existing_af->runtime);
    } else {
        eigrp_result_t res = eigrp_af_config_create(inst_name, EIGRP_AFI_IPV6, ni, asn);
        if (res != EIGRP_RESULT_SUCCESS) {
            pthread_mutex_lock(&g_data_lock);
            g_pending_netinst[0] = '\0';
            pthread_mutex_unlock(&g_data_lock);
            fprintf(stderr, "CSHIM V6: failed to create AF config %s: res=%d\n", inst_name, res);
            return -1;
        }
    }

    eigrp_instance_t *runtime = srl_instance_get_afi(ni, EIGRP_AFI_IPV6);
    if (!runtime) {
        pthread_mutex_lock(&g_data_lock);
        g_pending_netinst[0] = '\0';
        pthread_mutex_unlock(&g_data_lock);
        fprintf(stderr, "CSHIM V6: runtime not found after create\n");
        return -1;
    }

    // Set router-id
    eigrp_af_config_t *af = eigrp_af_config_read(inst_name, EIGRP_AFI_IPV6, ni, asn);
    if (router_id && router_id[0]) {
        struct in_addr r_addr;
        if (inet_pton(AF_INET, router_id, &r_addr) == 1) {
            eigrp_instance_context_t ctx;
            memset(&ctx, 0, sizeof(ctx));
            ctx.runtime = runtime;
            ctx.config = af;
            eigrp_instance_router_id_update(EIGRP_SET, &ctx, ntohl(r_addr.s_addr));
        }
    } else {
        eigrp_instance_t *v4_inst = srl_instance_get_afi(ni, EIGRP_AFI_IPV4);
        if (v4_inst && v4_inst->router_id.s_addr != INADDR_ANY) {
            eigrp_instance_context_t ctx;
            memset(&ctx, 0, sizeof(ctx));
            ctx.runtime = runtime;
            ctx.config = af;
            eigrp_instance_router_id_update(EIGRP_SET, &ctx, ntohl(v4_inst->router_id.s_addr));
        }
    }

    // Scan interfaces in netns now that the IPv6 runtime is ready
    srlShimInterfacesScan(ni);

    // Register all IPv6 interfaces with runtime
    typedef struct {
        char ifname[64];
        eigrp_ifindex_t ifindex;
        eigrp_prefix_t address_v6;
        uint32_t bandwidth;
        uint32_t mtu;
        bool has_global;
        char global_pfx[128];
        char global_ip[INET6_ADDRSTRLEN];
    } v6_if_snapshot_t;

    v6_if_snapshot_t v6_snaps[32];
    int snap_count = 0;

    pthread_mutex_lock(&g_data_lock);
    for (srl_intf_t *ci = g_interfaces; ci && snap_count < 32; ci = ci->next) {
        if (strcmp(ci->netinst, ni) != 0) continue;
        if (!ci->active_v6) continue;
        eigrp_prefix_t cur_v6 = ci->address_v6;
        if (cur_v6.address.afi != EIGRP_AFI_IPV6 && ci->global_v6.address.afi == EIGRP_AFI_IPV6) {
            cur_v6 = ci->global_v6;
        }
        if (cur_v6.address.afi == EIGRP_AFI_IPV6) {
            v6_snaps[snap_count].ifindex = ci->ifindex;
            v6_snaps[snap_count].address_v6 = cur_v6;
            v6_snaps[snap_count].bandwidth = ci->bandwidth;
            v6_snaps[snap_count].mtu = ci->mtu;
            strncpy(v6_snaps[snap_count].ifname, ci->ifname, sizeof(v6_snaps[snap_count].ifname) - 1);
            v6_snaps[snap_count].ifname[sizeof(v6_snaps[snap_count].ifname) - 1] = '\0';

            if (ci->global_v6.address.afi == EIGRP_AFI_IPV6 && ci->global_v6.prefix_length > 0) {
                char ip_buf[INET6_ADDRSTRLEN];
                v6_snaps[snap_count].has_global = true;
                inet_ntop(AF_INET6, ci->global_v6.address.bytes, ip_buf, sizeof(ip_buf));
                strncpy(v6_snaps[snap_count].global_ip, ip_buf, sizeof(v6_snaps[snap_count].global_ip) - 1);
                v6_snaps[snap_count].global_ip[sizeof(v6_snaps[snap_count].global_ip) - 1] = '\0';
                snprintf(v6_snaps[snap_count].global_pfx, sizeof(v6_snaps[snap_count].global_pfx), "%s/%u",
                         ip_buf, ci->global_v6.prefix_length);
            } else {
                v6_snaps[snap_count].has_global = false;
            }
            snap_count++;
        }
    }

    for (int i = 0; i < snap_count; i++) {
        eigrp_intf_runtime_state_t st;
        memset(&st, 0, sizeof(st));
        st.interface_name = v6_snaps[i].ifname;
        st.ifindex = v6_snaps[i].ifindex;
        st.address = v6_snaps[i].address_v6;
        st.type = 1;
        st.secondary = false;
        st.operative = true;
        st.bandwidth = v6_snaps[i].bandwidth;
        st.mtu = v6_snaps[i].mtu;
        eigrp_intf_runtime_update(EIGRP_SET, runtime, &st, NULL);

        if (v6_snaps[i].has_global) {
            srlShimRouteOriginateV6(ni, v6_snaps[i].global_pfx, NULL);
        }
    }
    g_pending_netinst[0] = '\0';
    pthread_mutex_unlock(&g_data_lock);

    return 0;
}

/* ------------------------------------------------------------------------
 * RIB Scale & Metric Update
 * ------------------------------------------------------------------------ */
typedef struct srl_rib_scale_entry {
    char netinst[64];
    uint8_t scale;
    struct srl_rib_scale_entry *next;
} srl_rib_scale_entry_t;

static srl_rib_scale_entry_t *g_rib_scales = NULL;

void srl_set_rib_scale(const char *netinst, uint8_t scale) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    if (scale == 0) scale = 128;
    pthread_mutex_lock(&g_data_lock);
    srl_rib_scale_entry_t *e = g_rib_scales;
    while (e) {
        if (strcmp(e->netinst, ni) == 0) {
            e->scale = scale;
            pthread_mutex_unlock(&g_data_lock);
            return;
        }
        e = e->next;
    }
    e = calloc(1, sizeof(*e));
    strncpy(e->netinst, ni, sizeof(e->netinst) - 1);
    e->scale = scale;
    e->next = g_rib_scales;
    g_rib_scales = e;
    pthread_mutex_unlock(&g_data_lock);
}

uint8_t srl_get_rib_scale(const char *netinst) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    pthread_mutex_lock(&g_data_lock);
    srl_rib_scale_entry_t *e = g_rib_scales;
    while (e) {
        if (strcmp(e->netinst, ni) == 0) {
            uint8_t s = e->scale;
            pthread_mutex_unlock(&g_data_lock);
            return s ? s : 128;
        }
        e = e->next;
    }
    pthread_mutex_unlock(&g_data_lock);
    return 128;
}

int srlShimMetricsUpdate(const char *netinst, uint8_t k1, uint8_t k2, uint8_t k3, uint8_t k4, uint8_t k5, uint8_t k6, uint8_t rib_scale, bool wide_metrics) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    srl_set_rib_scale(ni, rib_scale);
    eigrp_metric_weights_t weights;
    memset(&weights, 0, sizeof(weights));
    weights.tos = 0;
    weights.k1 = k1;
    weights.k2 = k2;
    weights.k3 = k3;
    weights.k4 = k4;
    weights.k5 = k5;
    weights.k6 = k6;

    eigrp_instance_t *instances[32];
    int count = 0;
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b && count < 32; b = b->next) {
        if (strcmp(b->netinst, ni) == 0 && b->eigrp) {
            instances[count++] = b->eigrp;
            b->eigrp->metric_version = wide_metrics ? EIGRP_TLV_64B_VERSION : EIGRP_TLV_32B_VERSION;
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    for (int i = 0; i < count; i++) {
        eigrp_instance_context_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.runtime = instances[i];
        eigrp_metric_weights_update(EIGRP_SET, &ctx, &weights);
    }
    return 0;
}

/* ------------------------------------------------------------------------
 * Authentication & Keychains
 * ------------------------------------------------------------------------ */
typedef struct srl_keychain_entry {
    char name[64];
    uint32_t key_id;
    char key_string[256];
    char algo[32];
    struct srl_keychain_entry *next;
} srl_keychain_entry_t;

static srl_keychain_entry_t *g_keychains = NULL;
static pthread_mutex_t g_keychain_lock = PTHREAD_MUTEX_INITIALIZER;

int srlShimKeychainAdd(const char *name, uint32_t key_id, const char *key_string, const char *algo) {
    if (!name || !key_string) return -1;
    char plain_key[256] = {0};
    srl_decrypt_password(key_string, plain_key, sizeof(plain_key));

    pthread_mutex_lock(&g_keychain_lock);
    srl_keychain_entry_t *e = g_keychains;
    while (e) {
        if (strcmp(e->name, name) == 0 && e->key_id == key_id) {
            strncpy(e->key_string, plain_key, sizeof(e->key_string) - 1);
            if (algo) strncpy(e->algo, algo, sizeof(e->algo) - 1);
            pthread_mutex_unlock(&g_keychain_lock);
            return 0;
        }
        e = e->next;
    }
    e = calloc(1, sizeof(*e));
    strncpy(e->name, name, sizeof(e->name) - 1);
    e->key_id = key_id;
    strncpy(e->key_string, plain_key, sizeof(e->key_string) - 1);
    if (algo) strncpy(e->algo, algo, sizeof(e->algo) - 1);
    e->next = g_keychains;
    g_keychains = e;
    pthread_mutex_unlock(&g_keychain_lock);
    return 0;
}

int srlShimKeychainDel(const char *name) {
    if (!name) return -1;
    pthread_mutex_lock(&g_keychain_lock);
    srl_keychain_entry_t **curr = &g_keychains;
    while (*curr) {
        if (strcmp((*curr)->name, name) == 0) {
            srl_keychain_entry_t *to_free = *curr;
            *curr = (*curr)->next;
            free(to_free);
        } else {
            curr = &(*curr)->next;
        }
    }
    pthread_mutex_unlock(&g_keychain_lock);
    return 0;
}

bool eigrp_sys_auth_key_lookup(const char *keychain_name, uint32_t *key_id, char *key_string, size_t key_string_size) {
    if (!keychain_name || !keychain_name[0] || !key_id || !key_string || key_string_size == 0) {
        return false;
    }
    pthread_mutex_lock(&g_keychain_lock);
    if (*key_id > 0) {
        for (srl_keychain_entry_t *kc = g_keychains; kc; kc = kc->next) {
            if (strcmp(kc->name, keychain_name) == 0 && kc->key_id == *key_id) {
                strncpy(key_string, kc->key_string, key_string_size - 1);
                key_string[key_string_size - 1] = '\0';
                pthread_mutex_unlock(&g_keychain_lock);
                return true;
            }
        }
    }
    for (srl_keychain_entry_t *kc = g_keychains; kc; kc = kc->next) {
        if (strcmp(kc->name, keychain_name) == 0) {
            *key_id = kc->key_id;
            strncpy(key_string, kc->key_string, key_string_size - 1);
            key_string[key_string_size - 1] = '\0';
            pthread_mutex_unlock(&g_keychain_lock);
            return true;
        }
    }
    pthread_mutex_unlock(&g_keychain_lock);
    return false;
}

int srlShimInterfaceAuthSetAfi(const char *netinst, const char *ifname, const char *afi, const char *mode, const char *keychain, const char *auth_key) {
    if (!ifname) return -1;
    if (!mode || strcasecmp(mode, "none") == 0) {
        return srlShimInterfaceAuthClearAfi(netinst, ifname, afi);
    }
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    uint8_t auth_type = EIGRP_AUTH_TYPE_NONE;
    if (strcasecmp(mode, "md5") == 0) {
        auth_type = EIGRP_AUTH_TYPE_MD5;
    } else if (strcasecmp(mode, "hmac-sha-256") == 0 || strcasecmp(mode, "sha256") == 0) {
        auth_type = EIGRP_AUTH_TYPE_SHA256;
    } else {
        return -1;
    }

    char decrypted_key[256] = {0};
    if (auth_key && auth_key[0]) {
        srl_decrypt_password(auth_key, decrypted_key, sizeof(decrypted_key));
    }

    int target_afi = -1;
    if (afi && afi[0]) {
        if (strcasecmp(afi, "ipv4-unicast") == 0 || strcasecmp(afi, "ipv4") == 0) {
            target_afi = (int)EIGRP_AFI_IPV4;
        } else if (strcasecmp(afi, "ipv6-unicast") == 0 || strcasecmp(afi, "ipv6") == 0) {
            target_afi = (int)EIGRP_AFI_IPV6;
        }
    }

    pthread_mutex_lock(&g_data_lock);
    char actual_ifname[64] = {0};
    eigrp_ifindex_t ifidx = 0;
    for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
        if (strcmp(ci->netinst, ni) == 0 && srl_match_ifname(ci->ifname, ifname)) {
            strncpy(actual_ifname, ci->ifname, sizeof(actual_ifname) - 1);
            ifidx = ci->ifindex;
            if (target_afi == (int)EIGRP_AFI_IPV4) {
                strncpy(ci->auth_mode_v4, mode, sizeof(ci->auth_mode_v4) - 1);
                if (keychain && keychain[0]) strncpy(ci->keychain_v4, keychain, sizeof(ci->keychain_v4) - 1);
                else ci->keychain_v4[0] = '\0';
                if (decrypted_key[0]) strncpy(ci->auth_key_v4, decrypted_key, sizeof(ci->auth_key_v4) - 1);
                else ci->auth_key_v4[0] = '\0';
            } else if (target_afi == (int)EIGRP_AFI_IPV6) {
                strncpy(ci->auth_mode_v6, mode, sizeof(ci->auth_mode_v6) - 1);
                if (keychain && keychain[0]) strncpy(ci->keychain_v6, keychain, sizeof(ci->keychain_v6) - 1);
                else ci->keychain_v6[0] = '\0';
                if (decrypted_key[0]) strncpy(ci->auth_key_v6, decrypted_key, sizeof(ci->auth_key_v6) - 1);
                else ci->auth_key_v6[0] = '\0';
            } else {
                strncpy(ci->auth_mode, mode, sizeof(ci->auth_mode) - 1);
                if (keychain && keychain[0]) strncpy(ci->keychain, keychain, sizeof(ci->keychain) - 1);
                else ci->keychain[0] = '\0';
                if (decrypted_key[0]) strncpy(ci->auth_key, decrypted_key, sizeof(ci->auth_key) - 1);
                else ci->auth_key[0] = '\0';
            }
            break;
        }
    }

    for (srl_binding_t *b = g_bindings; b; b = b->next) {
        if (strcmp(b->netinst, ni) == 0 && b->eigrp) {
            if (target_afi != -1 && (int)eigrp_instance_afi(b->eigrp) != target_afi) {
                continue;
            }
            eigrp_intf_t *ei = NULL;
            if (actual_ifname[0]) {
                ei = eigrp_intf_lookup_by_name(b->eigrp, actual_ifname);
            }
            if (!ei && ifidx > 0) {
                ei = eigrp_intf_lookup_by_ifindex(b->eigrp, ifidx);
            }
            if (!ei) {
                ei = eigrp_intf_lookup_by_name(b->eigrp, ifname);
            }
            if (ei) {
                if (ei->params.auth_password) {
                    memset(ei->params.auth_password, 0, strlen(ei->params.auth_password));
                    free(ei->params.auth_password);
                    ei->params.auth_password = NULL;
                }
                if (decrypted_key[0]) {
                    ei->params.auth_password = strdup(decrypted_key);
                }
                if (ei->params.auth_keychain) {
                    free(ei->params.auth_keychain);
                    ei->params.auth_keychain = NULL;
                }
                if (keychain && keychain[0]) {
                    ei->params.auth_keychain = strdup(keychain);
                }
                ei->params.auth_type = auth_type;
            }
        }
    }
    pthread_mutex_unlock(&g_data_lock);
    return 0;
}

int srlShimInterfaceAuthSet(const char *netinst, const char *ifname, const char *mode, const char *keychain, const char *auth_key) {
    return srlShimInterfaceAuthSetAfi(netinst, ifname, NULL, mode, keychain, auth_key);
}

int srlShimInterfaceAuthClearAfi(const char *netinst, const char *ifname, const char *afi) {
    if (!ifname) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    int target_afi = -1;
    if (afi && afi[0]) {
        if (strcasecmp(afi, "ipv4-unicast") == 0 || strcasecmp(afi, "ipv4") == 0) {
            target_afi = (int)EIGRP_AFI_IPV4;
        } else if (strcasecmp(afi, "ipv6-unicast") == 0 || strcasecmp(afi, "ipv6") == 0) {
            target_afi = (int)EIGRP_AFI_IPV6;
        }
    }

    pthread_mutex_lock(&g_data_lock);
    char actual_ifname[64] = {0};
    eigrp_ifindex_t ifidx = 0;
    for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
        if (strcmp(ci->netinst, ni) == 0 && srl_match_ifname(ci->ifname, ifname)) {
            strncpy(actual_ifname, ci->ifname, sizeof(actual_ifname) - 1);
            ifidx = ci->ifindex;
            if (target_afi == (int)EIGRP_AFI_IPV4) {
                ci->auth_mode_v4[0] = '\0';
                ci->keychain_v4[0] = '\0';
                ci->auth_key_v4[0] = '\0';
            } else if (target_afi == (int)EIGRP_AFI_IPV6) {
                ci->auth_mode_v6[0] = '\0';
                ci->keychain_v6[0] = '\0';
                ci->auth_key_v6[0] = '\0';
            } else {
                ci->auth_mode[0] = '\0';
                ci->keychain[0] = '\0';
                ci->auth_key[0] = '\0';
                ci->auth_mode_v4[0] = '\0';
                ci->keychain_v4[0] = '\0';
                ci->auth_key_v4[0] = '\0';
                ci->auth_mode_v6[0] = '\0';
                ci->keychain_v6[0] = '\0';
                ci->auth_key_v6[0] = '\0';
            }
            break;
        }
    }

    for (srl_binding_t *b = g_bindings; b; b = b->next) {
        if (strcmp(b->netinst, ni) == 0 && b->eigrp) {
            if (target_afi != -1 && (int)eigrp_instance_afi(b->eigrp) != target_afi) {
                continue;
            }
            eigrp_intf_t *ei = NULL;
            if (actual_ifname[0]) {
                ei = eigrp_intf_lookup_by_name(b->eigrp, actual_ifname);
            }
            if (!ei && ifidx > 0) {
                ei = eigrp_intf_lookup_by_ifindex(b->eigrp, ifidx);
            }
            if (!ei) {
                ei = eigrp_intf_lookup_by_name(b->eigrp, ifname);
            }
            if (ei) {
                ei->params.auth_type = EIGRP_AUTH_TYPE_NONE;
                if (ei->params.auth_password) {
                    memset(ei->params.auth_password, 0, strlen(ei->params.auth_password));
                    free(ei->params.auth_password);
                    ei->params.auth_password = NULL;
                }
                if (ei->params.auth_keychain) {
                    free(ei->params.auth_keychain);
                    ei->params.auth_keychain = NULL;
                }
            }
        }
    }
    pthread_mutex_unlock(&g_data_lock);
    return 0;
}

int srlShimInterfaceAuthClear(const char *netinst, const char *ifname) {
    return srlShimInterfaceAuthClearAfi(netinst, ifname, NULL);
}

/* ------------------------------------------------------------------------
 * Graceful Restart & Shutdown
 * ------------------------------------------------------------------------ */
typedef struct srl_gr_entry {
    char netinst[64];
    bool enabled;
    uint16_t restart_time;
    bool helper_mode;
    struct srl_gr_entry *next;
} srl_gr_entry_t;

static srl_gr_entry_t *g_gr_entries = NULL;

int srlShimGracefulRestartUpdate(const char *netinst, bool enabled, uint16_t restart_time, bool helper_mode) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    pthread_mutex_lock(&g_data_lock);
    srl_gr_entry_t *e = g_gr_entries;
    while (e) {
        if (strcmp(e->netinst, ni) == 0) {
            e->enabled = enabled;
            e->restart_time = restart_time;
            e->helper_mode = helper_mode;
            pthread_mutex_unlock(&g_data_lock);
            return 0;
        }
        e = e->next;
    }
    e = calloc(1, sizeof(*e));
    strncpy(e->netinst, ni, sizeof(e->netinst) - 1);
    e->enabled = enabled;
    e->restart_time = restart_time;
    e->helper_mode = helper_mode;
    e->next = g_gr_entries;
    g_gr_entries = e;
    pthread_mutex_unlock(&g_data_lock);
    return 0;
}

int srlShimGracefulShutdown(const char *netinst) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    eigrp_intf_t *intfs[64];
    int count = 0;
    pthread_mutex_lock(&g_data_lock);
    for (srl_binding_t *b = g_bindings; b; b = b->next) {
        if (strcmp(b->netinst, ni) == 0 && b->eigrp && b->eigrp->eiflist) {
            eigrp_list_item_t *node;
            eigrp_intf_t *ei;
            for (EIGRP_LIST_ITERATE_RO(b->eigrp->eiflist, node, ei)) {
                if (ei && count < 64) {
                    intfs[count++] = ei;
                }
            }
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    for (int i = 0; i < count; i++) {
        eigrp_hello_send(intfs[i], EIGRP_HELLO_GRACEFUL_SHUTDOWN, NULL);
    }
    return 0;
}

int srlShimStaticNeighborAdd(const char *netinst, const char *ip_str, const char *ifname) {
    if (!ip_str || !ifname) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    pthread_mutex_lock(&g_data_lock);
    char actual_ifname[64];
    strncpy(actual_ifname, ifname, sizeof(actual_ifname) - 1);
    actual_ifname[sizeof(actual_ifname) - 1] = '\0';
    for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
        if (strcmp(ci->netinst, ni) == 0 && srl_match_ifname(ci->ifname, ifname)) {
            strncpy(actual_ifname, ci->ifname, sizeof(actual_ifname) - 1);
            break;
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    bool is_v6 = (strchr(ip_str, ':') != NULL);
    eigrp_instance_t *runtime = srl_instance_get_afi(ni, is_v6 ? EIGRP_AFI_IPV6 : EIGRP_AFI_IPV4);
    if (!runtime) {
        return 0;
    }

    eigrp_af_config_t *af = eigrp_af_config_runtime_read(runtime);
    if (!af) {
        return -1;
    }

    eigrp_address_t addr;
    memset(&addr, 0, sizeof(addr));
    addr.afi = is_v6 ? EIGRP_AFI_IPV6 : EIGRP_AFI_IPV4;
    int res = inet_pton(is_v6 ? AF_INET6 : AF_INET, ip_str, addr.bytes);
    if (res != 1) {
        return -1;
    }

    eigrp_result_t er = eigrp_nbr_static_create(af, &addr, actual_ifname);
    return (er == EIGRP_RESULT_SUCCESS) ? 0 : -1;
}

int srlShimStaticNeighborDel(const char *netinst, const char *ip_str, const char *ifname) {
    if (!ip_str) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    pthread_mutex_lock(&g_data_lock);
    char actual_ifname[64];
    if (ifname && ifname[0]) {
        strncpy(actual_ifname, ifname, sizeof(actual_ifname) - 1);
        actual_ifname[sizeof(actual_ifname) - 1] = '\0';
        for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
            if (strcmp(ci->netinst, ni) == 0 && srl_match_ifname(ci->ifname, ifname)) {
                strncpy(actual_ifname, ci->ifname, sizeof(actual_ifname) - 1);
                break;
            }
        }
    } else {
        actual_ifname[0] = '\0';
    }
    pthread_mutex_unlock(&g_data_lock);

    bool is_v6 = (strchr(ip_str, ':') != NULL);
    eigrp_instance_t *runtime = srl_instance_get_afi(ni, is_v6 ? EIGRP_AFI_IPV6 : EIGRP_AFI_IPV4);
    if (!runtime) {
        return 0;
    }

    eigrp_af_config_t *af = eigrp_af_config_runtime_read(runtime);
    if (!af) {
        return -1;
    }

    eigrp_address_t addr;
    memset(&addr, 0, sizeof(addr));
    addr.afi = is_v6 ? EIGRP_AFI_IPV6 : EIGRP_AFI_IPV4;
    int res = inet_pton(is_v6 ? AF_INET6 : AF_INET, ip_str, addr.bytes);
    if (res != 1) {
        return -1;
    }

    eigrp_result_t er = eigrp_nbr_static_delete(af, &addr, actual_ifname[0] ? actual_ifname : NULL);
    return (er == EIGRP_RESULT_SUCCESS) ? 0 : -1;
}

int srlShimSummaryAddressAdd(const char *netinst, const char *ifname, const char *prefix_str, uint8_t distance) {
    if (!ifname || !prefix_str) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    pthread_mutex_lock(&g_data_lock);
    char actual_ifname[64];
    strncpy(actual_ifname, ifname, sizeof(actual_ifname) - 1);
    actual_ifname[sizeof(actual_ifname) - 1] = '\0';
    for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
        if (strcmp(ci->netinst, ni) == 0 && srl_match_ifname(ci->ifname, ifname)) {
            strncpy(actual_ifname, ci->ifname, sizeof(actual_ifname) - 1);
            break;
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    char pfx_copy[128];
    strncpy(pfx_copy, prefix_str, sizeof(pfx_copy) - 1);
    pfx_copy[sizeof(pfx_copy) - 1] = '\0';
    char *slash = strchr(pfx_copy, '/');
    uint8_t plen = 0;
    if (slash) {
        *slash = '\0';
        plen = (uint8_t)atoi(slash + 1);
    }

    bool is_v6 = (strchr(pfx_copy, ':') != NULL);
    if (plen == 0) {
        plen = is_v6 ? 128 : 32;
    }

    eigrp_afi_t afi = is_v6 ? EIGRP_AFI_IPV6 : EIGRP_AFI_IPV4;
    eigrp_instance_t *runtime = srl_instance_get_afi(ni, afi);
    if (!runtime) {
        return 0;
    }

    eigrp_af_config_t *af = eigrp_af_config_runtime_read(runtime);
    if (!af) {
        return -1;
    }

    eigrp_intf_t *ei = eigrp_intf_lookup_by_name(runtime, actual_ifname);
    eigrp_intf_config_t *ic = eigrp_intf_config_read(af, actual_ifname);
    if (!ic) {
        eigrp_intf_config_create(af, actual_ifname);
        ic = eigrp_intf_config_read(af, actual_ifname);
    }
    if (!ic) {
        return -1;
    }

    eigrp_intf_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.address_family = af;
    ctx.config = ic;
    ctx.runtime = ei;

    eigrp_prefix_t pfx;
    memset(&pfx, 0, sizeof(pfx));
    pfx.address.afi = afi;
    pfx.prefix_length = plen;
    if (inet_pton(is_v6 ? AF_INET6 : AF_INET, pfx_copy, pfx.address.bytes) != 1) {
        return -1;
    }

    eigrp_summary_options_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.administrative_distance = distance ? distance : 5;

    eigrp_result_t er = eigrp_summary_create(&ctx, &pfx, &opts);
    return (er == EIGRP_RESULT_SUCCESS) ? 0 : -1;
}

int srlShimSummaryAddressDelete(const char *netinst, const char *ifname, const char *prefix_str) {
    if (!ifname || !prefix_str) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";

    pthread_mutex_lock(&g_data_lock);
    char actual_ifname[64];
    strncpy(actual_ifname, ifname, sizeof(actual_ifname) - 1);
    actual_ifname[sizeof(actual_ifname) - 1] = '\0';
    for (srl_intf_t *ci = g_interfaces; ci; ci = ci->next) {
        if (strcmp(ci->netinst, ni) == 0 && srl_match_ifname(ci->ifname, ifname)) {
            strncpy(actual_ifname, ci->ifname, sizeof(actual_ifname) - 1);
            break;
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    char pfx_copy[128];
    strncpy(pfx_copy, prefix_str, sizeof(pfx_copy) - 1);
    pfx_copy[sizeof(pfx_copy) - 1] = '\0';
    char *slash = strchr(pfx_copy, '/');
    uint8_t plen = 0;
    if (slash) {
        *slash = '\0';
        plen = (uint8_t)atoi(slash + 1);
    }

    bool is_v6 = (strchr(pfx_copy, ':') != NULL);
    if (plen == 0) {
        plen = is_v6 ? 128 : 32;
    }

    eigrp_afi_t afi = is_v6 ? EIGRP_AFI_IPV6 : EIGRP_AFI_IPV4;
    eigrp_instance_t *runtime = srl_instance_get_afi(ni, afi);
    if (!runtime) {
        return 0;
    }

    eigrp_af_config_t *af = eigrp_af_config_runtime_read(runtime);
    if (!af) {
        return -1;
    }

    eigrp_intf_t *ei = eigrp_intf_lookup_by_name(runtime, actual_ifname);
    eigrp_intf_config_t *ic = eigrp_intf_config_read(af, actual_ifname);
    if (!ic) {
        return 0;
    }

    eigrp_intf_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.address_family = af;
    ctx.config = ic;
    ctx.runtime = ei;

    eigrp_prefix_t pfx;
    memset(&pfx, 0, sizeof(pfx));
    pfx.address.afi = afi;
    pfx.prefix_length = plen;
    if (inet_pton(is_v6 ? AF_INET6 : AF_INET, pfx_copy, pfx.address.bytes) != 1) {
        return -1;
    }

    eigrp_result_t er = eigrp_summary_delete(&ctx, &pfx);
    return (er == EIGRP_RESULT_SUCCESS) ? 0 : -1;
}

int srlShimDistanceUpdate(const char *netinst, uint8_t internal_dist, uint8_t external_dist) {
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    eigrp_instance_t *r4 = srl_instance_get_afi(ni, EIGRP_AFI_IPV4);
    if (r4) {
        eigrp_af_config_t *af4 = eigrp_af_config_runtime_read(r4);
        if (af4) {
            (void)eigrp_af_config_distance_update(EIGRP_SET, af4, internal_dist, external_dist);
        }
    }
    eigrp_instance_t *r6 = srl_instance_get_afi(ni, EIGRP_AFI_IPV6);
    if (r6) {
        eigrp_af_config_t *af6 = eigrp_af_config_runtime_read(r6);
        if (af6) {
            (void)eigrp_af_config_distance_update(EIGRP_SET, af6, internal_dist, external_dist);
        }
    }
    return 0;
}

int srlShimDistanceUpdateAfi(const char *netinst, const char *afi_name, uint8_t internal_dist, uint8_t external_dist) {
    if (!afi_name) return -1;
    const char *ni = (netinst && netinst[0]) ? netinst : "default";
    eigrp_afi_t afi = (strcmp(afi_name, "ipv6-unicast") == 0) ? EIGRP_AFI_IPV6 : EIGRP_AFI_IPV4;
    eigrp_instance_t *r = srl_instance_get_afi(ni, afi);
    if (r) {
        eigrp_af_config_t *af = eigrp_af_config_runtime_read(r);
        if (af) {
            (void)eigrp_af_config_distance_update(EIGRP_SET, af, internal_dist, external_dist);
        }
    }
    return 0;
}
