/*
 * Copyright 2025 Corey Minyard
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This is a test driver to test the IPMI driver on Linux.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <gensio/gensio.h>
#include <gensio/gensio_openipmi_oshandler.h>
#include <gensio/gensio_list.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/internal/ipmi_event.h>

static int debug;

struct tinfo;

/*
 * Messages to and from the helper app are handled with this structure.
 */
struct helperbuf {
    struct gensio_link link;
    struct tinfo *ti;
    gensiods len;
    gensiods pos;
    unsigned char *data;
    unsigned long long id;
    bool free_after_send;
    bool needs_resp;
    bool sent;
    bool done;
    bool got_resp;
    int rc;

    char response[512];
};

/*
 * Message to and from ipmi_sim are handled here.
 */
struct ipmibuf {
    struct gensio_link link;
    struct tinfo *ti;
    ipmi_msgi_t *msgi;
    bool done;
    bool free_on_done;
};

/*
 * Commands sent by the helper to here are handled through this.
 */
struct cmdwaiter {
    struct gensio_link link;
    struct tinfo *ti;
    struct helperbuf *sb;
    /* Returns true if the command was handled, false if not. */
    int (*handler)(struct cmdwaiter *cw, long long cid, unsigned int devidx,
		   const char *addr, uint8_t netfn, uint8_t cmd,
		   const char *data);
    bool done;
};

struct tinfo {
    int rv;

    unsigned long long curr_id;

    struct gensio_os_funcs *o;
    struct gensio *helper;

    os_handler_t *oo;
    ipmi_con_t *icon;

    struct gensio_waiter *waiter;

    /* A waiter that is never woken, just use for sleeping. */
    struct gensio_waiter *sleeper;

    bool ready;
    bool closing;
    bool ipmi_open;
    unsigned int close_wait_count;

    char inbuf[1024];
    gensiods inbuf_len;

    /* List of struct helperbuf to write. */
    struct gensio_list writelist;

    /* List of struct helperbuf waiting for a response. */
    struct gensio_list waitlist;

    /* List of struct cmdwaiter waiting for a command from the helper. */
    struct gensio_list cmdwaitlist;
};

static void start_test_close(struct tinfo *ti);

static void
do_vlog(struct gensio_os_funcs *f, enum gensio_log_levels level,
	const char *log, va_list args)
{
    fprintf(stderr, "gensio %s log: ", gensio_log_level_to_str(level));
    vfprintf(stderr, log, args);
    fprintf(stderr, "\n");
}

/*
 * Why couldn't the C designers have a function that would copy a
 * string, truncate when it was too big for the destination and return
 * if it truncated?
 */
static int
copy_string(char *dst, const char *src, gensiods len)
{
    unsigned int i;

    if (len == 0)
	return GE_INVAL;

    for (i = 0; src[i] && i < len - 1; i++)
	dst[i] = src[i];
    dst[i] = '\0';
    if (src[i])
	return GE_TOOBIG;
    return 0;
}

static void
i_pr_err(const char *file, unsigned int line, char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s Line %u: ", file, line);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
#define pr_err(fmt, ...) i_pr_err(__FILE__, __LINE__, fmt, __VA_ARGS__)

static int
get_uint(char *name, char **str, bool allow_end, unsigned int *rval)
{
    char *end, *s = *str;
    int val;

    if (!isdigit(s[0])) {
	pr_err("Invalid number %s in %s\n", s, name);
	return 1;
    }

    val = strtoul(s, &end, 0);
    if (*end == ' ') {
	end++;
    } else if (!allow_end || *end != '\0') {
	pr_err("Invalid number %s in %s\n", s, name);
	return 1;
    }

    *str = end;
    *rval = val;
    return 0;
}

static int
get_long_long(char *name, char **str, bool allow_end, long long *rval)
{
    char *end, *s = *str;
    int val;

    if (!isdigit(s[0])) {
	pr_err("Invalid number %s in %s\n", s, name);
	return 1;
    }

    val = strtoll(s, &end, 0);
    if (*end == ' ') {
	end++;
    } else if (!allow_end || *end != '\0') {
	pr_err("Invalid number %s in %s\n", s, name);
	return 1;
    }

    *str = end;
    *rval = val;
    return 0;
}

static int
get_ulong_long(char *name, char **str, bool allow_end, unsigned long long *rval)
{
    char *end, *s = *str;
    int val;

    if (!isdigit(s[0])) {
	pr_err("Invalid number %s in %s\n", s, name);
	return 1;
    }

    val = strtoull(s, &end, 0);
    if (*end == ' ') {
	end++;
    } else if (!allow_end || *end != '\0') {
	pr_err("Invalid number %s in %s\n", s, name);
	return 1;
    }

    *str = end;
    *rval = val;
    return 0;
}

static int
get_hex_byte(char *name, char **str, bool allow_end, uint8_t *rval)
{
    char *end, *s = *str;
    int val;

    if (!isxdigit(s[0])) {
	pr_err("Invalid number %s in %s\n", s, name);
	return 1;
    }

    val = strtoul(s, &end, 16);
    if (*end == ' ') {
	end++;
    } else if (!allow_end || *end != '\0' || val > 255) {
	pr_err("Invalid number %s in %s\n", s, name);
	return 1;
    }

    *str = end;
    *rval = val;
    return 0;
}

static char *
get_addr(char *name, char **str, bool allow_end)
{
    char *s = *str, *rv;
    int skip, mode;

    if (strncmp(s, "si ", 3) == 0) {
	skip = 2;
	s += 3;
    } else if (strncmp(s, "ipmb ", 5) == 0) {
	skip = 3;
	s += 5;
    } else if (strncmp(s, "lan ", 4) == 0) {
	skip = 6;
	s += 4;
    } else {
	pr_err("Invalid address %s in %s\n", *str, name);
	return NULL;
    }
    for (mode = 0; skip > 0; s++) {
	if (!*s) {
	    pr_err("Invalid address %s in %s\n", *str, name);
	    return NULL;
	}
	if (mode == 0) {
	    if (!isxdigit(*s)) {
		pr_err("Invalid address %s in %s\n", *str, name);
		return NULL;
	    }
	    mode = 1;
	} else if (mode == 1) {
	    if (isxdigit(*s)) {
		/* It's what we want. */
	    } else if (*s == ' ' || *s == '\0') {
		skip--;
		mode = 0;
	    } else {
		pr_err("Invalid address %s in %s\n", *str, name);
		return NULL;
	    }
	}
    }
    rv = *str;
    if (*s) {
	*s = '\0';
	*str = s + 1;
    } else if (!allow_end) {
	pr_err("Invalid address %s in %s\n", *str, name);
	return NULL;
    }

    return rv;
}

static struct ipmibuf *
alloc_ipmibuf(struct tinfo *ti)
{
    struct gensio_os_funcs *o = ti->o;
    struct ipmibuf *ib;

    ib = gensio_os_funcs_zalloc(o, sizeof(*ib));
    if (!ib)
	return NULL;

    ib->msgi = ipmi_alloc_msg_item();
    if (!ib->msgi) {
	gensio_os_funcs_zfree(o, ib);
	return NULL;
    }

    ib->msgi->data1 = ib;
    ib->ti = ti;
    return ib;
}

static void
free_ipmibuf(struct ipmibuf *ib)
{
    ipmi_free_msg_item(ib->msgi);
    gensio_os_funcs_zfree(ib->ti->o, ib);
}

static int
ipmi_rsp_handler(ipmi_con_t *icon, ipmi_msgi_t *rspi)
{
    struct ipmibuf *ib = rspi->data1;

    if (ib->free_on_done)
	free_ipmibuf(ib);
    else
	ib->done = true;
    return IPMI_MSG_ITEM_USED;
}

static int
send_ipmi_msg(struct tinfo *ti, ipmi_addr_t *addr, unsigned int addrlen,
	      uint8_t netfn, uint8_t cmd, uint8_t *data, unsigned int datalen,
	      struct ipmibuf **rib)
{
    struct ipmibuf *ib;
    ipmi_msg_t msg;
    int rv;

    ib = alloc_ipmibuf(ti);
    if (!ib)
	return GE_NOMEM;

    msg.netfn = netfn;
    msg.cmd = cmd;
    msg.data = data;
    msg.data_len = datalen;

    rv = ti->icon->send_command(ti->icon, addr, addrlen, &msg,
				ipmi_rsp_handler, ib->msgi);
    if (rv) {
	if (IPMI_IS_OS_ERR(rv))
	    rv = gensio_os_err_to_err(ti->o, IPMI_OS_ERR_VAL(rv));
	else
	    rv = GE_COMMERR;
	gensio_os_funcs_zfree(ti->o, ib);
	return rv;
    }

    *rib = ib;
    return 0;
}

static int
ipmi_wait_done(struct ipmibuf *ib)
{
    /* IPMI commands are supposed to always give responses.  Just in case... */
    gensio_time timeout = { 60, 0 };
    int rv;

    while (!ib->done && !ib->ti->rv) {
	rv = gensio_os_funcs_service(ib->ti->o, &timeout);
	if (rv && rv != GE_INTERRUPTED)
	    return rv;
    }
    if (ib->ti->rv)
	return ib->ti->rv;
    return 0;
}

static int
ipmi_cmd_resp(struct tinfo *ti, ipmi_addr_t *addr, unsigned int addrlen,
	      uint8_t netfn, uint8_t cmd, uint8_t *data, unsigned int datalen,
	      bool allow_cmd_fail, struct ipmibuf **rib)
{
    struct ipmibuf *ib;
    int rv;

    rv = send_ipmi_msg(ti, addr, addrlen, netfn, cmd, data, datalen, &ib);
    if (rv) {
	pr_err("Unable to send IPMI message (%x %x): %s\n", netfn, cmd,
	       gensio_err_to_str(rv));
	return rv;
    }
    rv = ipmi_wait_done(ib);
    if (rv) {
	/* Don't free the buffer, but mark it to be freed on response. */
	pr_err("Failed waiting on IPMI message (%x %x): %s\n", netfn, cmd,
	       gensio_err_to_str(rv));
	ib->free_on_done = true;
	return rv;
    }

    /* Got a response. */

    if (ib->msgi->msg.data_len < 1) {
	pr_err("IPMI message rsp (%x %x) had no data.\n", netfn, cmd);
	free_ipmibuf(ib);
	return GE_INVAL;
    }

    if (!allow_cmd_fail && ib->msgi->msg.data[0]) {
	pr_err("IPMI message rsp (%x %x) had error 0x%x.\n", netfn, cmd,
	       ib->msgi->msg.data[0]);
	free_ipmibuf(ib);
	return GE_INVAL;
    }

    if (!rib)
	free_ipmibuf(ib);
    else
	*rib = ib;
    return 0;
}

static struct helperbuf *
alloc_helperbuf(struct tinfo *ti, const char *cmd, const char *str, va_list ap)
{
    struct gensio_os_funcs *o = ti->o;
    struct helperbuf *s;
    va_list ap2;
    size_t len, len2;
    char dummy[21];

    va_copy(ap2, ap);
    len = vsnprintf(dummy, 21, str, ap);
    len += snprintf(dummy, 21, "%s %llu ", cmd, ti->curr_id);
    s = gensio_os_funcs_zalloc(o, sizeof(struct helperbuf) + len + 2);
    if (!s)
	return NULL;
    s->len = len + 1;
    s->pos = 0;
    s->data = ((unsigned char *) s) + sizeof(*s);
    len2 = snprintf((char *) s->data, len + 1, "%s %llu ", cmd, ti->curr_id);
    vsnprintf(((char *) s->data) + len2, len - len2 + 1, str, ap2);
    va_end(ap2);
    s->data[len] = '\n';
    s->data[len + 1] = '\0';
    s->ti = ti;
    s->id = ti->curr_id++;
    copy_string(s->response, "No Response", sizeof(s->response));

    return s;
}

static void
helperbuf_free(struct helperbuf *sb)
{
    gensio_os_funcs_zfree(sb->ti->o, sb);
}

static void
helperbuf_unlink_free(struct tinfo *ti, struct helperbuf *sb)
{
    if (sb->sent)
	gensio_list_rm(&ti->waitlist, &sb->link);
    else
	gensio_list_rm(&ti->writelist, &sb->link);
    helperbuf_free(sb);
}

static struct helperbuf *
helper_vsend(struct tinfo *ti, const char *cmd, const char *str, va_list ap)
{
    struct helperbuf *s;

    s = alloc_helperbuf(ti, cmd, str, ap);
    gensio_list_add_tail(&ti->writelist, &s->link);
    gensio_set_write_callback_enable(ti->helper, true);
    s->needs_resp = strcmp(cmd, "Command") == 0 || strcmp(cmd, "Response") == 0;

    return s;
}

__attribute__ ((__format__ (__printf__, 3, 4)))
static struct helperbuf *
helper_send_cmd(struct tinfo *ti, const char *cmd, const char *str, ...)
{
    va_list ap;
    struct helperbuf *s;

    va_start(ap, str);
    s = helper_vsend(ti, cmd, str, ap);
    va_end(ap);
    if (!s) {
	pr_err("Out of memory sending command '%s %s\n", cmd, str);
	return NULL;
    }

    return s;
}

static int
helper_wait_done(struct helperbuf *sb)
{
    gensio_time timeout = { 30, 0 };
    int rv;

    if (sb->needs_resp) {
	while (!sb->got_resp && !sb->rc && !sb->ti->rv) {
	    rv = gensio_os_funcs_service(sb->ti->o, &timeout);
	    if (rv && rv != GE_INTERRUPTED)
		return rv;
	}
    } else {
	while (!sb->done && !sb->ti->rv) {
	    rv = gensio_os_funcs_service(sb->ti->o, &timeout);
	    if (rv && rv != GE_INTERRUPTED)
		return rv;
	}
    }
    if (sb->ti->rv)
	return sb->ti->rv;
    if (!sb->got_resp && sb->response[0])
	return -1;
    return 0;
}

static void
helper_wait_done_print_err(int rv, struct helperbuf *sb,
			   const char *cmd, const char *str)
{
    if (rv > 0) {
	pr_err("Command %s %s: Error waiting on helperbuf: %s\n",
	       cmd, str, gensio_err_to_str(rv));
    } else if (rv < 0) {
	pr_err("Command %s %s: Load error response: %s\n",
	       cmd, str, sb->response);
    }
}

__attribute__ ((__format__ (__printf__, 4, 5)))
int
helper_cmd_resp(struct tinfo *ti, struct helperbuf **rsb,
		const char *cmd, const char *str, ...)
{
    va_list ap;
    struct helperbuf *sb;
    int rv;

    va_start(ap, str);
    sb = helper_vsend(ti, cmd, str, ap);
    va_end(ap);

    if (!sb) {
	pr_err("Unable to send command '%s %s'", cmd, str);
	return 1;
    }
    rv = helper_wait_done(sb);
    if (rv) {
	helper_wait_done_print_err(rv, sb, cmd, str);
	rv = 1;
    }
    if (rsb)
	*rsb = sb;
    else
	helperbuf_unlink_free(sb->ti, sb);
    return rv;
}

static int
test_load_unload(struct tinfo *ti)
{
    int rv;

    rv = helper_cmd_resp(ti, NULL, "Load", "ipmi_msghandler");
    if (rv)
	return rv;
    rv = helper_cmd_resp(ti, NULL, "Unload", "ipmi_msghandler");
    if (rv)
	return rv;
    rv = helper_cmd_resp(ti, NULL, "Load", "i2c-i801 ipmi_msghandler ipmi_si ipmi_devintf ipmi_ssif");
    rv = helper_cmd_resp(ti, NULL, "Unload", "ipmi_ssif ipmi_devintf ipmi_si ipmi_msghandler i2c-i801");
    if (rv)
	return rv;

    rv = helper_cmd_resp(ti, NULL, "Cycle", "10 i2c-i801 ipmi_msghandler ipmi_si ipmi_devintf ipmi_ssif");
    if (rv)
	return rv;

    return 0;
}

static int
verify_file_contents(struct tinfo *ti, const char *dir, const char *file,
		     const char *contents)
{
    int rv;
    struct helperbuf *sb;

    rv = helper_cmd_resp(ti, &sb, "Runcmd", "cat %s/%s", dir, file);
    if (rv)
	return rv;
    if (sb->rc) {
	pr_err("Unable to cat %s/%s\n", dir, file);
	return 1;
    }
    if (strcmp(contents, sb->response) != 0) {
	pr_err("Contents of %s/%s don't match, expected '%s', got '%s'\n",
	       dir, file, contents, sb->response);
	return 1;
    }
    helperbuf_unlink_free(ti, sb);
    return 0;
}

static int
test_bmcs(struct tinfo *ti)
{
    int rv;
    struct helperbuf *sb;
    char *t, *saveptr;
    bool found = false, found2 = false;
    gensio_time timeout = { 2, 0 };

    rv = helper_cmd_resp(ti, NULL, "Load", "i2c-i801 ipmi_msghandler ipmi_devintf ipmi_ssif");
    if (rv)
	return rv;

    /* Give a little time for the driver to create everything. */
    gensio_os_funcs_wait(ti->o, ti->sleeper, 1, &timeout);

    rv = helper_cmd_resp(ti, &sb, "Runcmd", "ls /sys/bus/platform/devices");
    if (rv)
	return rv;
    if (sb->rc) {
	pr_err("Dump BMCs 1 failed (%d): %s\n", sb->rc, sb->response);
	helperbuf_unlink_free(ti, sb);
	return 1;
    }

    t = strtok_r(sb->response, "\n", &saveptr);
    while(t) {
	if (strncmp(t, "ipmi_bmc.", 9) == 0) {
	    if (strcmp(t, "ipmi_bmc.0") == 0) {
		found = true;
	    } else {
		pr_err("Unknown BMC on system: %s\n", t);
		return 1;
	    }
	}
	t = strtok_r(NULL, "\n", &saveptr);
    }
    if (!found) {
	pr_err("ipmi_bmc.0 not found on system: %s\n", t);
	return 1;
    }

    helperbuf_unlink_free(ti, sb);

    rv = helper_cmd_resp(ti, NULL, "Load", "ipmi_si");
    if (rv)
	return rv;

    rv = helper_cmd_resp(ti, &sb, "Runcmd", "ls /sys/bus/platform/devices");
    if (rv)
	return rv;
    if (sb->rc) {
	pr_err("Dump BMCs 1 failed (%d): %s\n", sb->rc, sb->response);
	helperbuf_unlink_free(ti, sb);
	return 1;
    }

    found = false;
    t = strtok_r(sb->response, "\n", &saveptr);
    while(t) {
	if (strncmp(t, "ipmi_bmc.", 9) == 0) {
	    if (strcmp(t, "ipmi_bmc.0") == 0) {
		found = true;
	    } else if (strcmp(t, "ipmi_bmc.1") == 0) {
		found2 = true;
	    } else {
		pr_err("Unknown BMC on system: %s\n", t);
		return 1;
	    }
	}
	t = strtok_r(NULL, "\n", &saveptr);
    }
    if (!found) {
	pr_err("ipmi_bmc.0 not found on system: %s\n", t);
	return 1;
    }
    if (!found2) {
	pr_err("ipmi_bmc.1 not found on system: %s\n", t);
	return 1;
    }
    helperbuf_unlink_free(ti, sb);

    /* Verify ipmisim fields, must match ipmisim1.emu. */
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.0",
			     "device_id", "0\n"))
	return 1;
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.0",
			     "provides_device_sdrs", "0\n"))
	return 1;
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.0",
			     "revision", "3\n"))
	return 1;
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.0",
			     "firmware_revision", "9.8\n"))
	return 1;
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.0",
			     "additional_device_support", "0x9f\n"))
	return 1;
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.0",
			     "manufacturer_id", "0x001291\n"))
	return 1;
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.0",
			     "product_id", "0x0f02\n"))
	return 1;
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.0",
			     "ipmi_version", "2.0\n"))
	return 1;

    /* Verify simulated fields, must match what's in qemu's ipmi_bmc_sim.c. */
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.1",
			     "device_id", "32\n"))
	return 1;
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.1",
			     "provides_device_sdrs", "0\n"))
	return 1;
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.1",
			     "revision", "0\n"))
	return 1;
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.1",
			     "firmware_revision", "0.0\n"))
	return 1;
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.1",
			     "additional_device_support", "0x07\n"))
	return 1;
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.1",
			     "manufacturer_id", "0x000000\n"))
	return 1;
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.1",
			     "product_id", "0x0000\n"))
	return 1;
    if (verify_file_contents(ti, "/sys/bus/platform/devices/ipmi_bmc.0",
			     "ipmi_version", "2.0\n"))
	return 1;

    rv = helper_cmd_resp(ti, NULL, "Unload",
			 "ipmi_si ipmi_ssif ipmi_devintf ipmi_msghandler i2c-i801");
    if (rv)
	return rv;

    rv = helper_cmd_resp(ti, &sb, "Runcmd", "ls /sys/bus/platform/devices");
    if (rv)
	return rv;
    if (sb->rc) {
	pr_err("Dump BMCs 2 failed (%d): %s\n", sb->rc, sb->response);
	helperbuf_unlink_free(ti, sb);
	return 1;
    }

    t = strtok_r(sb->response, "\n", &saveptr);
    while(t) {
	if (strncmp(t, "ipmi_bmc.", 9) == 0) {
	    pr_err("Unknown BMC on system: %s\n", t);
	    return 1;
	}
	t = strtok_r(NULL, "\n", &saveptr);
    }
    helperbuf_unlink_free(ti, sb);

    return 0;
}

static int
test_cmd(struct tinfo *ti)
{
    int rv;
    struct helperbuf *sb, *sb2, *sb3, *sb4;
    static char *bmc0_getdevid_rsp =
	"0 si 0f 00 07 01 00 00 03 09 08 02 9f 91 12 00 02 0f 00 00 00 00";
    static char *mc30_getdevid_rsp =
	"0 ipmb 00 30 00 07 01 00 02 08 10 01 02 a0 91 12 00 03 0f 00 00 00 00";
    unsigned int count;
    unsigned int restart_count = 0;
    const char *module = "ipmi_ssif";
    gensio_time timeout;

    rv = helper_cmd_resp(ti, NULL, "Load", "i2c-i801 ipmi_msghandler ipmi_devintf ipmi_ssif");
    if (rv)
	return rv;

 restart:
    /* Give a little time for the driver to create everything. */
    timeout.secs = 2;
    timeout.nsecs = 0;
    gensio_os_funcs_wait(ti->o, ti->sleeper, 1, &timeout);

    rv = helper_cmd_resp(ti, NULL, "Open", "0 0");
    if (rv)
	return rv;

    rv = helper_cmd_resp(ti, &sb, "Command", "0 si f 0 6 1");
    if (rv)
	return rv;
    if (strcmp(sb->response, bmc0_getdevid_rsp) != 0) {
	pr_err("Invalid BMC get devid resp, expected '%s', got '%s'\n",
	       bmc0_getdevid_rsp, sb->response);
	helperbuf_unlink_free(ti, sb);
	return 1;
    }
    helperbuf_unlink_free(ti, sb);

    rv = helper_cmd_resp(ti, &sb, "Command", "0 ipmb 0 30 0 6 1");
    if (rv)
	return rv;
    if (strcmp(sb->response, mc30_getdevid_rsp) != 0) {
	pr_err("Invalid BMC get devid resp, expected '%s', got '%s'\n",
	       bmc0_getdevid_rsp, sb->response);
	helperbuf_unlink_free(ti, sb);
	return 1;
    }
    helperbuf_unlink_free(ti, sb);

    /* Send a number of commands and wait for all the responses. */
    sb = helper_send_cmd(ti, "Command", "0 si f 0 6 1");
    if (!sb)
	return 1;
    sb2 = helper_send_cmd(ti, "Command", "0 ipmb 0 30 0 6 1");
    if (!sb2)
	return 1;
    sb3 = helper_send_cmd(ti, "Command", "0 si f 0 6 1");
    if (!sb3)
	return 1;
    sb4 = helper_send_cmd(ti, "Command", "0 ipmb 0 30 0 6 1");
    if (!sb4)
	return 1;
    rv = helper_wait_done(sb4);
    if (rv)
	return rv;
    if (strcmp(sb4->response, mc30_getdevid_rsp) != 0) {
	pr_err("Invalid BMC get devid resp, expected '%s', got '%s'\n",
	       bmc0_getdevid_rsp, sb4->response);
	return 1;
    }
    rv = helper_wait_done(sb3);
    if (rv)
	return rv;
    if (strcmp(sb3->response, bmc0_getdevid_rsp) != 0) {
	pr_err("Invalid BMC get devid resp, expected '%s', got '%s'\n",
	       bmc0_getdevid_rsp, sb3->response);
	return 1;
    }
    rv = helper_wait_done(sb2);
    if (rv)
	return rv;
    if (strcmp(sb2->response, mc30_getdevid_rsp) != 0) {
	pr_err("Invalid BMC get devid resp, expected '%s', got '%s'\n",
	       bmc0_getdevid_rsp, sb2->response);
	return 1;
    }
    rv = helper_wait_done(sb);
    if (rv)
	return rv;
    if (strcmp(sb->response, bmc0_getdevid_rsp) != 0) {
	pr_err("Invalid BMC get devid resp, expected '%s', got '%s'\n",
	       bmc0_getdevid_rsp, sb->response);
	return 1;
    }
    helperbuf_unlink_free(ti, sb4);
    helperbuf_unlink_free(ti, sb3);
    helperbuf_unlink_free(ti, sb2);
    helperbuf_unlink_free(ti, sb);

    /* Send a command and close. */
    sb3 = helper_send_cmd(ti, "Command", "0 si f 0 6 1");
    if (!sb3)
	return 1;
    /* Response may or may not make it back, but just ignore it. */
    sb3->free_after_send = true;

    rv = helper_cmd_resp(ti, NULL, "Close", "0");
    if (rv)
	return rv;

    count = 0;
    rv = 1;
    sb = helper_send_cmd(ti, "Unload", "%s", module);
    if (!sb)
	return 1;
    while (rv) {
	/*
	 * The close an take a bit of time to complete, so the module
	 * may still be in use for a bit.
	 */
	rv = helper_wait_done(sb);
	count++;
	if (count > 10)
	    break;
	if (rv) {
	    helperbuf_unlink_free(ti, sb);
	    sleep(1);
	    sb = helper_send_cmd(ti, "Unload", "%s", module);
	    if (!sb)
		return 1;
	}
    }
    if (rv) {
	helper_wait_done_print_err(rv, sb, "Unload", module);
	return 1;
    }
    helperbuf_unlink_free(ti, sb);

    if (restart_count == 0) {
	restart_count++;
	rv = helper_cmd_resp(ti, NULL, "Load", "ipmi_si");
	if (rv)
	    return 1;
	module = "ipmi_si";
	goto restart;
    }

    rv = helper_cmd_resp(ti, NULL, "Unload",
			 "ipmi_devintf ipmi_msghandler i2c-i801");
    if (rv)
	return rv;

    return 0;
}

static int
test_ipmilan_cmd(struct tinfo *ti)
{
    struct ipmibuf *ib;
    int rv;
    struct ipmi_system_interface_addr si;
    struct ipmi_ipmb_addr ipmb;

    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    rv = ipmi_cmd_resp(ti, (ipmi_addr_t *) &si, sizeof(si), 6, 1, NULL, 0,
		       false, &ib);
    if (rv)
	return rv;
    free_ipmibuf(ib);

    ipmb.addr_type = IPMI_IPMB_ADDR_TYPE;
    ipmb.channel = 0;
    ipmb.lun = 0;
    ipmb.slave_addr = 0x30; /* Simulated satellite BMC. */
    rv = ipmi_cmd_resp(ti, (ipmi_addr_t *) &ipmb, sizeof(ipmb),
		       6, 1, NULL, 0, false, &ib);
    if (rv)
	return rv;
    free_ipmibuf(ib);

    return 0;
}

static int
cmd_handler(struct cmdwaiter *cw, long long cid, unsigned int devidx,
	    const char *addr, uint8_t netfn, uint8_t cmd,
	    const char *data)
{
    struct tinfo *ti = cw->ti;

    if (devidx != 0 || netfn != 6 || cmd != 1)
	return 0;

    cw->sb = helper_send_cmd(ti, "Response", "%u %lld %s 7 1 1 2 3 4",
			     devidx, cid, addr);
    if (!cw->sb) {
	printf("Out of memory sending response\n");
	return 1;
    }
    cw->done = true;
    gensio_list_rm(&ti->cmdwaitlist, &cw->link);
    return 1;
}

static int
test_host_cmd(struct tinfo *ti)
{
    struct ipmibuf *ib = NULL;
    int rv;
    struct ipmi_system_interface_addr si;
    struct cmdwaiter cw;
    gensio_time timeout;

    memset(&cw, 0, sizeof(cw));

    rv = helper_cmd_resp(ti, NULL, "Load", "ipmi_msghandler ipmi_devintf ipmi_si");
    if (rv)
	return rv;

    /* Give a little time for the driver to create everything. */
    timeout.secs = 2;
    timeout.nsecs = 0;
    gensio_os_funcs_wait(ti->o, ti->sleeper, 1, &timeout);

    rv = helper_cmd_resp(ti, NULL, "Open", "0 0");
    if (rv)
	return rv;

    /* Send the command, no handler. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 2;
    rv = ipmi_cmd_resp(ti, (ipmi_addr_t *) &si, sizeof(si), 6, 1, NULL, 0,
		       true, &ib);
    if (rv)
	goto out_err;
    if (ib->msgi->msg.data[0] != 0xc1) {
	pr_err("Did not get C1 error from unhandled command, got %2.2x\n",
	       ib->msgi->msg.data[0]);
	rv = 1;
	goto out_err;
    }
    free_ipmibuf(ib);
    ib = NULL;

    /* Set up a handler to receive the command. */
    cw.ti = ti;
    cw.handler = cmd_handler;
    gensio_list_add_tail(&ti->cmdwaitlist, &cw.link);

    /* Register for the command. */
    rv = helper_cmd_resp(ti, NULL, "Register", "0 6 1");
    if (rv)
	goto out_err;

    rv = send_ipmi_msg(ti, (ipmi_addr_t *) &si, sizeof(si), 6, 1, NULL, 0, &ib);
    if (rv)
	goto out_err;

    timeout.secs = 10;
    timeout.nsecs = 0;
    while (!ti->rv && !cw.done) {
	rv = gensio_os_funcs_service(ti->o, &timeout);
	if (rv && rv != GE_INTERRUPTED) {
	    pr_err("Error waiting on received command: %s\n",
		   gensio_err_to_str(rv));
	    goto out_err;
	}
    }

    rv = helper_wait_done(cw.sb);
    if (rv)
	helper_wait_done_print_err(rv, cw.sb, "Response", "");

    rv = ipmi_wait_done(ib);
    if (rv) {
	/* Don't free the buffer, but mark it to be freed on response. */
	pr_err("Failed to get host command respone\n", gensio_err_to_str(rv));
	ib->free_on_done = true;
	ib = NULL;
	return rv;
    }

    rv = helper_cmd_resp(ti, NULL, "Close", "0");
    if (rv)
	return rv;

    rv = helper_cmd_resp(ti, NULL, "Unload",
			 "ipmi_devintf ipmi_si ipmi_msghandler");
    if (rv)
	return rv;

 out_err:
    if (ib)
	free_ipmibuf(ib);
    if (cw.sb)
	helperbuf_free(cw.sb);
    return rv;
}

#define NUM_PANIC_EVENTS 3
#define PANIC_EVENT_SIZE 14
static uint8_t panic_events[NUM_PANIC_EVENTS][PANIC_EVENT_SIZE] = {
    { 0x02, 0xcf, 0xcf, 0x51, 0x00, 0x41, 0xf0,
      0x03, 0x20, 0x73, 0x6f, 0xa1, 0x79, 0x73, },
    { 0xf0, 0x20, 0x00, 0x73, 0x79, 0x73, 0x72,
      0x71, 0x20, 0x74, 0x72, 0x69, 0x67, 0x67, },
    { 0xf0, 0x20, 0x01, 0x65, 0x72, 0x65, 0x64,
      0x20, 0x63, 0x72, 0x61, 0x73, 0x68, 0x00, },
};

static int
test_panic_events(struct tinfo *ti)
{
    int rv;
    struct ipmibuf *ib;
    struct ipmi_system_interface_addr si;
    gensio_time timeout = { 2, 0 };
    uint8_t clr_sel_cmddata[6] = { 0x00, 0x00, 'C', 'L', 'R', 0xaa };
    uint8_t get_sel_cmddata[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0xff };
    uint8_t chassis_reset_cmddata[1] = { 0x3 };
    unsigned int i;

    rv = helper_cmd_resp(ti, NULL, "Load", "ipmi_msghandler ipmi_devintf ipmi_si");
    if (rv)
	goto out_err;

    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;

    /* Clear the SEL. */
    rv = ipmi_cmd_resp(ti, (ipmi_addr_t *) &si, sizeof(si),
		       IPMI_STORAGE_NETFN, IPMI_CLEAR_SEL_CMD,
		       clr_sel_cmddata, sizeof(clr_sel_cmddata),
		       false, NULL);
    if (rv)
	goto out_err;

    rv = helper_cmd_resp(ti, NULL, "Panic", "0");
    if (rv)
	goto out_err;

    rv = gensio_close_s(ti->helper);
    if (rv) {
	pr_err("Error closing connection: %s\n", gensio_err_to_str(rv));
	goto out_err;
    }

    /* Make sure the events have to to get into the event queue. */
    gensio_os_funcs_wait(ti->o, ti->sleeper, 1, &timeout);

    /* Fetch the events. */
    for (i = 0; ; i++) {
	uint8_t next1, next2;
	bool cmp;

	if (i >= NUM_PANIC_EVENTS) {
	    pr_err("Too many panic events: %d\n", i);
	    rv = 1;
	    goto out_err;
	}

	rv = ipmi_cmd_resp(ti, (ipmi_addr_t *) &si, sizeof(si),
			   IPMI_STORAGE_NETFN, IPMI_GET_SEL_ENTRY_CMD,
			   get_sel_cmddata, sizeof(get_sel_cmddata),
			   false, &ib);
	if (rv)
	    goto out_err;
	
	if (ib->msgi->msg.data_len < 19) {
	    pr_err("Invalid SEL get size: %d\n", ib->msgi->msg.data_len);
	    rv = 1;
	    goto out_err;
	}
	if (panic_events[i][0] == 2) {
	    /* Event type 2 has a timestamp in bytes 1-4, so ignore those. */
	    cmp = panic_events[i][0] != ib->msgi->msg.data[5] ||
		memcmp(ib->msgi->msg.data + 10, panic_events[i] + 5,
		       PANIC_EVENT_SIZE - 5);
	} else {
	    cmp = memcmp(ib->msgi->msg.data + 5, panic_events[i],
			 PANIC_EVENT_SIZE);
	}
	if (cmp) {
	    char buf1[100], buf2[100], *s;
	    unsigned int j;

	    for (s = buf1, j = 0; j < 14; j++)
		s += sprintf(s, " %2.2x", ib->msgi->msg.data[j + 5]);
	    for (s = buf2, j = 0; j < 14; j++)
		s += sprintf(s, " %2.2x", panic_events[i][j]);
	    pr_err("Invalid panic event data on event %d, expected %s, got %s\n",
		   i, buf2, buf1);
	    rv = 1;
	    goto out_err;
	}
	next1 = ib->msgi->msg.data[1];
	next2 = ib->msgi->msg.data[2];
#if 0
	printf("RSP:");
	for (i = 0; i < 19; i++)
	    printf(" %2.2x", ib->msgi->msg.data[i]);
	printf("\n");
#endif
	free_ipmibuf(ib);
	if (next1 == 0xff && next2 == 0xff)
	    break;
	get_sel_cmddata[2] = next1;
	get_sel_cmddata[3] = next2;
    }

    /* Now reset the device. */
    rv = ipmi_cmd_resp(ti, (ipmi_addr_t *) &si, sizeof(si),
		       IPMI_CHASSIS_NETFN, IPMI_CHASSIS_CONTROL_CMD,
		       chassis_reset_cmddata, sizeof(chassis_reset_cmddata),
		       false, NULL);
    if (rv)
	goto out_err;

    /* Wait for the reset to complete. */
    timeout.secs = 10;
    timeout.nsecs = 0;
    gensio_os_funcs_wait(ti->o, ti->sleeper, 1, &timeout);

    rv = gensio_open_s(ti->helper);
    if (rv) {
	pr_err("Error reopening helper connection: %s\n", gensio_err_to_str(rv));
	goto out_err;
    }
    gensio_set_read_callback_enable(ti->helper, true);

 out_err:
    return rv;
}

struct teststr {
    char *name;
    int (*testfn)(struct tinfo *ti);
} tests[] = {
    { "Test loading and unloading modules", test_load_unload },
    { "Test BMC creation and removal", test_bmcs },
    { "Test basic commands", test_cmd },
    { "Test basic IPMI LAN commands", test_ipmilan_cmd },
    { "Test commands to host", test_host_cmd },
    { "Test panic events", test_panic_events },
    {}
};

static int
run_test(struct tinfo *ti, struct teststr *test)
{
    int rv;

    printf("%s...", test->name);
    fflush(stdout);
    rv = test->testfn(ti);
    if (rv) {
	printf(" failed\n");
	ti->rv = 1;
	return 1;
    }
    printf(" passed\n");
    return 0;
}

static void
run_tests(struct tinfo *ti, int testnum)
{
    unsigned int i;
    int rv;

    if (testnum >= 0) {
	unsigned int n = testnum;

	for (i = 0; tests[i].name; i++) {
	    if (i == n) {
		run_test(ti, &tests[i]);
		return;
	    }
	}
    }

    for (i = 0; tests[i].name; i++) {
	rv = run_test(ti, &tests[i]);
	if (rv)
	    break;
    }
}
	
static void
ipmi_event_handler(ipmi_con_t        *ipmi,
		   const ipmi_addr_t *addr,
		   unsigned int      addr_len,
		   ipmi_event_t      *event,
		   void              *cb_data)
{
    unsigned int        record_id = ipmi_event_get_record_id(event);
    unsigned int        type = ipmi_event_get_type(event);
    unsigned int        data_len = ipmi_event_get_data_len(event);
    const unsigned char *data = ipmi_event_get_data_ptr(event);
    unsigned int        i;

    printf("Got event:\n");
    printf("  %4.4x (%2.2x):", record_id, type);
    for (i=0; i<data_len; i++)
	printf(" %2.2x", data[i]);
    printf("\n");
}

static struct helperbuf *
find_waiting_helperbuf(struct tinfo *ti, bool allow_end, char **idptr)
{
    unsigned long long id;
    struct gensio_link *l;

    if (get_ulong_long("Helper id", idptr, allow_end, &id))
	return NULL;
    gensio_list_for_each(&ti->waitlist, l) {
	struct helperbuf *sb = gensio_container_of(l, struct helperbuf, link);

	if (sb->id == id) {
	    return sb;
	}
    }
    return NULL;
}

static void
handle_buf(struct tinfo *ti)
{
    char *end;
    struct helperbuf *sb;

    if (debug)
	printf("Recv: '%s'\n", ti->inbuf);
    if (strcmp(ti->inbuf, "Ready") == 0) {
	/* Just ignore this. */
    } else if (strncmp(ti->inbuf, "Done ", 5) == 0) {
	end = ti->inbuf + 5;
	sb = find_waiting_helperbuf(ti, true, &end);
	if (!sb) {
	    pr_err("Unknown done: %s\n", ti->inbuf);
	} else if (!sb->needs_resp && sb->free_after_send) {
	    helperbuf_unlink_free(ti, sb);
	} else {
	    if (*end == ' ') {
		/* Got an error. */
		sb->rc = 1;
		end++;
	    }
	    copy_string(sb->response, end, sizeof(sb->response));
	    sb->done = true;
	}
    } else if (strncmp(ti->inbuf, "Panic ", 6) == 0) {
	end = ti->inbuf + 6;
	sb = find_waiting_helperbuf(ti, true, &end);
	if (!sb) {
	    pr_err("Unknown panic: %s\n", ti->inbuf);
	} else if (!sb->needs_resp && sb->free_after_send) {
	    helperbuf_unlink_free(ti, sb);
	} else {
	    sb->done = true;
	    sb->response[0] = '\0';
	}
    } else if (strncmp(ti->inbuf, "Runrsp ", 7) == 0) {
	end = ti->inbuf + 7;
	sb = find_waiting_helperbuf(ti, false, &end);
	if (!sb) {
	    pr_err("Unknown Runrsp: %s\n", ti->inbuf);
	} else {
	    if (*end == ' ')
		end++;
	    sb->rc = strtol(end, &end, 0);
	    if (*end == ' ')
		end++;
	    copy_string(sb->response, end, sizeof(sb->response));
	    sb->done = true;
	    sb->got_resp = true;
	}
    } else if (strncmp(ti->inbuf, "Response ", 9) == 0) {
	end = ti->inbuf + 9;
	sb = find_waiting_helperbuf(ti, false, &end);
	if (!sb) {
	    pr_err("Unknown response: %s\n", ti->inbuf);
	} else if (sb->free_after_send) {
	    helperbuf_unlink_free(ti, sb);
	} else if (!sb->done) {
	    pr_err("Response without done: %s\n", ti->inbuf);
	} else {
	    copy_string(sb->response, end, sizeof(sb->response));
	    sb->got_resp = true;
	}
    } else if (strncmp(ti->inbuf, "Command ", 8) == 0) {
	long long cid;
	unsigned int devidx;
	char *end = ti->inbuf + 8;
	char *addr;
	uint8_t netfn, cmd;
	struct gensio_link *l;
	bool handled = false;

	if (get_long_long(ti->inbuf, &end, false, &cid))
	    return;
	if (get_uint(ti->inbuf, &end, false, &devidx))
	    return;
	addr = get_addr(ti->inbuf, &end, false);
	if (!addr)
	    return;
	if (get_hex_byte(ti->inbuf, &end, false, &netfn))
	    return;
	if (get_hex_byte(ti->inbuf, &end, true, &cmd))
	    return;
	gensio_list_for_each(&ti->cmdwaitlist, l) {
	    struct cmdwaiter *cw = gensio_container_of(l, struct cmdwaiter,
						       link);
	    if (cw->handler(cw, cid, devidx, addr, netfn, cmd, end)) {
		handled = true;
		break;
	    }
	}
	if (!handled)
	    pr_err("Unhandled command: %s\n", ti->inbuf);
    } else if (strncmp(ti->inbuf, "ResponseResponse ", 17) == 0) {
	end = ti->inbuf + 17;
	sb = find_waiting_helperbuf(ti, false, &end);
	if (!sb) {
	    pr_err("Unknown responseresponse: %s\n", ti->inbuf);
	} else if (!sb->done) {
	    pr_err("Responseresponse without done: %s\n", ti->inbuf);
	} else {
	    copy_string(sb->response, end, sizeof(sb->response));
	    sb->got_resp = true;
	}
    } else {
	pr_err("Unknown response type: %s\n", ti->inbuf);
    }
}

static int
io_event(struct gensio *io, void *user_data, int event, int err,
	 unsigned char *buf, gensiods *buflen,
	 const char *const *auxdata)
{
    struct tinfo *ti = user_data;
    gensiods len, i;
    int rv;
    bool handle_it = false, in_runrsp = false;

    switch (event) {
    case GENSIO_EVENT_READ:
	if (ti->closing)
	    return 0;

	if (err) {
	    pr_err("Error from helper: %s\n", gensio_err_to_str(err));
	    ti->rv = 1;
	    start_test_close(ti);
	    return 0;
	}

	len = *buflen;
	for (i = 0; i < len; i++) {
	    if (in_runrsp) {
		if (buf[i] == '\0') {
		    ti->inbuf[ti->inbuf_len] = '\0';
		    handle_it = true;
		    i++;
		    break;
		}
	    } else if (buf[i] == '\n' || buf[i] == '\r' || buf[i] == '\0') {
		ti->inbuf[ti->inbuf_len] = '\0';

		if (buf[i] != '\0' && strncmp(ti->inbuf, "Runrsp ", 7) == 0) {
		    /* Runrsp is nil char terminated, special handling. */
		    in_runrsp = true;
		} else {
		    handle_it = true;
		    i++;
		    break;
		}
	    }
	    if (ti->inbuf_len >= sizeof(ti->inbuf) - 1)
		continue;
	    ti->inbuf[ti->inbuf_len++] = buf[i];
	}
	*buflen = i; /* We processed the characters up to the new line. */

	if (handle_it && ti->inbuf_len > 0) {
	    handle_buf(ti);
	    ti->inbuf_len = 0;
	}
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	if (ti->closing) {
	    gensio_set_write_callback_enable(ti->helper, false);
	    return 0;
	}

	while (!gensio_list_empty(&ti->writelist)) {
	    struct gensio_link *l = gensio_list_first(&ti->writelist);
	    struct helperbuf *sb = gensio_container_of(l, struct helperbuf,
						       link);

	    if (debug)
		printf("Send: '%s'\n", (char *) sb->data);
	    rv = gensio_write(ti->helper, &i,
			      sb->data + sb->pos, sb->len - sb->pos,
			      NULL);
	    if (rv) {
		if (rv != GE_REMCLOSE)
		    pr_err("Error writing to io: %s\n", gensio_err_to_str(rv));
		gensio_set_write_callback_enable(ti->helper, false);
		ti->rv = 1;
		start_test_close(ti);
		return 0;
	    }
	    sb->pos += i;
	    if (sb->pos >= sb->len) {
		gensio_list_rm(&ti->writelist, &sb->link);
		sb->sent = true;
		gensio_list_add_tail(&ti->waitlist, &sb->link);
	    } else {
		break;
	    }
	}
	if (gensio_list_empty(&ti->writelist))
	    gensio_set_write_callback_enable(ti->helper, false);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static void
ipmi_con_changed_handler(ipmi_con_t   *con,
			 int          err,
			 unsigned int port_num,
			 int          still_connected,
			 void         *cb_data)
{
    struct tinfo *ti = cb_data;

    if (ti->closing)
	return;

    if (err) {
	pr_err("IPMI connection failure: %x\n", err);
	ti->icon = NULL;
	con->close_connection(con);
	if (ti->ready)
	    start_test_close(ti);
    }

    if (!ti->ipmi_open) {
	gensio_os_funcs_wake(ti->o, ti->waiter);
	ti->ipmi_open = true;
    }
}

static void
helper_open_done(struct gensio *io, int err, void *open_data)
{
    struct tinfo *ti = open_data;

    if (ti->closing)
	return;

    if (err) {
	pr_err("helper connection failure: %s\n", gensio_err_to_str(err));
	gensio_free(io);
	ti->rv = 1;
	ti->helper = NULL;
	return;
    }

    gensio_set_read_callback_enable(ti->helper, true);
    gensio_os_funcs_wake(ti->o, ti->waiter);
}

static struct {
    char *name;
    char *value;
} ipmi_con_args[] = {
    { "Address", "localhost" },
    { "Port", "9001" },
    { "Username", "ipmiusr" },
    { "Password", "test" },
    {}
};

static int
ipmi_setup_con(struct tinfo *ti)
{
    ipmi_args_t *iargs;
    int rv;
    unsigned int i;

    ti->oo = gensio_openipmi_oshandler_alloc(ti->o);
    if (!ti->oo) {
	fprintf(stderr, "Could not allocate openipmi os handler\n");
	return 1;
    }

    rv = ipmi_init(ti->oo);
    if (rv) {
	fprintf(stderr, "Error initializing connections: 0x%x\n", rv);
	return 1;
    }

    rv = ipmi_args_alloc("lan", &iargs);
    if (rv) {
	fprintf(stderr, "Error allocating IPMI connection args: 0x%x\n", rv);
	return 1;
    }

    for (i = 0; ipmi_con_args[i].name; i++) {
	rv = ipmi_args_set_val(iargs, -1,
			       ipmi_con_args[i].name, ipmi_con_args[i].value);
	if (rv) {
	    fprintf(stderr, "Error setting IPMI con arg %s(%s): 0x%x\n",
		    ipmi_con_args[i].name, ipmi_con_args[i].value, rv);
	    return 1;
	}
    }

    rv = ipmi_args_setup_con(iargs, ti->oo, NULL, &ti->icon);
    if (rv) {
	fprintf(stderr, "Error setting up IPMI connection: 0x%x\n", rv);
	return 1;
    }
    ipmi_free_args(iargs);

    rv = ti->icon->add_event_handler(ti->icon, ipmi_event_handler, ti);
    if (rv) {
	fprintf(stderr, "Error setting up event handler: 0x%x\n", rv);
	return 1;
    }

    ti->icon->add_con_change_handler(ti->icon, ipmi_con_changed_handler, ti);

    rv = ti->icon->start_con(ti->icon);
    if (rv) {
	fprintf(stderr, "Could not start connection: %x\n", rv);
	return 1;
    }

    return 0;
}

static int
helper_setup_con(struct tinfo *ti)
{
    int rv;

    rv = str_to_gensio("tcp,localhost,2000", ti->o, io_event, ti, &ti->helper);
    if (rv) {
	fprintf(stderr, "Could not allocate gensio: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }

    rv = gensio_open(ti->helper, helper_open_done, ti);
    if (rv) {
	fprintf(stderr, "Could not open gensio: %s\n", gensio_err_to_str(rv));
	return 1;
    }

    return 0;
}

static void
ipmi_close_done(ipmi_con_t *ipmi, void *cb_data)
{
    struct tinfo *ti = cb_data;

    ti->close_wait_count--;
    if (ti->close_wait_count == 0)
	gensio_os_funcs_wake(ti->o, ti->waiter);
}

static void
helper_close_done(struct gensio *io, void *close_data)
{
    struct tinfo *ti = close_data;

    ti->close_wait_count--;
    if (ti->close_wait_count == 0)
	gensio_os_funcs_wake(ti->o, ti->waiter);
}

static void
start_test_close(struct tinfo *ti)
{
    int rv;

    ti->closing = true;

    if (ti->icon) {
	rv = ti->icon->close_connection_done(ti->icon, ipmi_close_done, ti);
	if (!rv)
	    ti->close_wait_count++;
    }

    if (ti->helper) {
	rv = gensio_close(ti->helper, helper_close_done, ti);
	if (rv)
	    gensio_free(ti->helper);
	else
	    ti->close_wait_count++;
    }

    if (ti->close_wait_count == 0)
	gensio_os_funcs_wake(ti->o, ti->waiter);
}

int
main(int argc, char *argv[])
{
    struct tinfo ti;
    struct gensio_os_proc_data *proc_data = NULL;
    int rv, testnum = -1;
    gensio_time timeout;
    int argp = 1;
    uint8_t chassis_on_cmddata[1] = { 0x1 };
    struct ipmi_system_interface_addr si;

    while (argp < argc && argv[argp][0] == '-') {
	if (strcmp(argv[argp], "-d") == 0) {
	    debug++;
	} else if (strcmp(argv[argp], "-l") == 0) {
	    unsigned int i;

	    for (i = 0; tests[i].name; i++)
		printf("%d: %s\n", i, tests[i].name);
	    return 0;
	} else {
	    fprintf(stderr, "Unknown option: %s\n", argv[argp]);
	    return 1;
	}
	argp++;
    }

    if (argp < argc)
	testnum = atoi(argv[argp]);

    memset(&ti, 0, sizeof(ti));

    gensio_list_init(&ti.writelist);
    gensio_list_init(&ti.waitlist);
    gensio_list_init(&ti.cmdwaitlist);

    rv = gensio_alloc_os_funcs(GENSIO_DEF_WAKE_SIG, &ti.o, 0);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    gensio_os_funcs_set_vlog(ti.o, do_vlog);

    rv = gensio_os_proc_setup(ti.o, &proc_data);
    if (rv) {
	fprintf(stderr, "Could not setup process data: %s\n",
		gensio_err_to_str(rv));
	ti.rv = 1;
	goto out_close;
    }

    ti.waiter = gensio_os_funcs_alloc_waiter(ti.o);
    if (!ti.waiter) {
	fprintf(stderr, "Could not allocate waiter, out of memory\n");
	ti.rv = 1;
	goto out_close;
    }

    ti.sleeper = gensio_os_funcs_alloc_waiter(ti.o);
    if (!ti.sleeper) {
	fprintf(stderr, "Could not allocate sleeper, out of memory\n");
	ti.rv = 1;
	goto out_close;
    }

    if (ipmi_setup_con(&ti)) {
	ti.rv = 1;
	goto out_close;
    }
    timeout.secs = 2;
    timeout.nsecs = 0;
    rv = gensio_os_funcs_wait(ti.o, ti.waiter, 1, &timeout);
    if (rv) {
	fprintf(stderr, "Error setting up IPMI connections: %s\n",
		gensio_err_to_str(rv));
	ti.rv = 1;
	goto out_close;
    }

    /*
     * Only power on and off the VM if running all the tests.  If only
     * running one test, assume the VM is already up.
     */
    if (testnum == -1) {
	printf("Powering on the virtual machine, this may take a bit...");
	fflush(stdout);
	si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si.channel = 0xf;
	si.lun = 0;
	rv = ipmi_cmd_resp(&ti, (ipmi_addr_t *) &si, sizeof(si),
			   IPMI_CHASSIS_NETFN, IPMI_CHASSIS_CONTROL_CMD,
			   chassis_on_cmddata, sizeof(chassis_on_cmddata),
			   false, NULL);
	if (rv) {
	    fprintf(stderr, "Could not power on virtual machine: %s\n",
		    gensio_err_to_str(rv));
	    goto out_wait_close;
	}
	/* Wait for power up to complete. */
	timeout.secs = 10;
	timeout.nsecs = 0;
	gensio_os_funcs_wait(ti.o, ti.sleeper, 1, &timeout);
	printf(" done\n");
    }

    if (helper_setup_con(&ti)) {
	ti.rv = 1;
	start_test_close(&ti);
	goto out_wait_close;
    }

    timeout.secs = 2;
    timeout.nsecs = 0;
    rv = gensio_os_funcs_wait(ti.o, ti.waiter, 1, &timeout);
    if (rv) {
	fprintf(stderr, "Error setting up connections: %s\n",
		gensio_err_to_str(rv));
	ti.rv = 1;
	goto out_close;
    }
    if (ti.rv)
	goto out_close;

    ti.ready = true;

    run_tests(&ti, testnum);

    if (testnum == -1 && !ti.rv) {
	struct helperbuf *sb;

	printf("Powering off the virtual machine\n");
	sb = helper_send_cmd(&ti, "Runcmd", "poweroff");
	if (!sb) {
	    fprintf(stderr, "Unable to send Runcmd poweroff");
	    goto out_close;
	}
	timeout.secs = 2;
	timeout.nsecs = 0;
	gensio_os_funcs_wait(ti.o, ti.sleeper, 1, &timeout);
	helperbuf_unlink_free(sb->ti, sb);
    }

    start_test_close(&ti);

 out_wait_close:
    rv = gensio_os_funcs_wait(ti.o, ti.waiter, 1, NULL);
    if (rv) {
	fprintf(stderr, "Error from wait: %s\n",
		gensio_err_to_str(rv));
	ti.rv = 1;
    }

 out_close:
    if (ti.waiter)
	gensio_os_funcs_free_waiter(ti.o, ti.waiter);
    if (ti.sleeper)
	gensio_os_funcs_free_waiter(ti.o, ti.sleeper);
    if (proc_data)
	gensio_os_proc_cleanup(proc_data);
    gensio_os_funcs_free(ti.o);

    return ti.rv;
}
