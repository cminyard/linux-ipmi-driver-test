/*
 * Copyright 2025 Corey Minyard
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * A program to test the IPMI driver on Linux.
 *
 * This program will create a socket that will allow a user to execute
 * certain commands.  This is designed to be used with a test driver
 * that starts QEMU using the OpenIPMI library's ipmi_sim program to
 * simulate an external BMC.  This program runs inside QEMU to allow
 * the test driver to do what it needs.
 *
 * This program expect the IPMI driver to be compiled as modules and all
 * the modules to be in the current directory.  We don't use the kernel
 * built by yocto/distro, as we are testing a new kernel.
 *
 *   Load <id> ipmi_msghandler|ipmi_si|ipmi_smbus|ipmi_devintf
 *     Load a driver.
 *   Unload <id> ipmi_msghandler|ipmi_si|ipmi_smbus|ipmi_devintf
 *     Unoad a driver.
 *   Cycle <id> <count> <module> [<module> [<module> [...]]]
 *     Cycle loading/unloading the given module(s) as fast as possible.
 *   Command <id> <devidx> <addr> <netfn> <cmd> <data>
 *     Send a command.
 *   Response <id> <devidx> <cid> <addr> <netfn> <cmd> <data>
 *     Send a response.  The <cid> should be the id that came in with the
 *     Command this is a response to.
 *   Broadcast <id> <devidx> <addr> <netfn> <cmd> <data>
 *     Send a broadcast.
 *   Register <id> <devidx> <netfn> <cmd> [<channels>]
 *     Register for command.
 *   Unregister <id> <devidx> <netfn> <cmd> [<channels>]
 *     Unregister for command.
 *   EvEnable <id> <devidx> <enable>
 *     Set event enable (1 or 0 for enable or disable).
 *   Open <id> <devidx> <dev>
 *     Open IPMI device.
 *   Close <id> <devidx>
 *     Close IPMI device.
 *   Panic <id>
 *     Panic the system to test the panic logs.
 *   Quit <id>
 *     Shut down the program.
 *   Runcmd <id> <shell command>
 *     Run the given command and return the response in Runrsp
 *   Write <id> <file> <data>
 *     Write some data to a file.
 *
 * <dev> is the particular IPMI device, 0-9.
 * <devidx> is an index into an array of open devices.  Note that you
 *   can open the same device twice in different indexes, this is useful
 *   for testing multiple users.
 *
 * <addr> is:
 *   si <channel> <lun> 
 *   ipmb <channel> <ipmb> <lun> 
 *   lan <channel> <privilege> <handle> <rSWID> <lSWID> <lun> 
 *
 * Asynchronous received data is:
 *   Done <id> [<err>]
 *     Command with the given id has completed.  If <err> is present, there
 *     was an error.
 *   Command <cid> <devidx> <addr> <netfn> <cmd> <data>
 *     A command from the BMC to handle.  Return the <cid> as <cid> in
 *     the Response.
 *   Event <devidx> <data>
 *     An event was received.
 *   Response <id> <devidx> err <errstr> |  <addr> <netfn> <cmd> <data>
 *     Response to a sent command.
 *   ResponseResponse <id> <devidx> [<err>]
 *     Response to a sent response.
 *   Closed <devidx>
 *     An error occurred and <devidx> was closed.
 *   Shutdown <id>
 *     The program was shut down.
 *   Panic <id>
 *     The system is about to panic.
 *   Runrsp <id> <return code> <output>
 *     The output of a Runcmd.  Note that the <output> is nil terminated,
 *     not newline terminated, so some special handling is required.  This
 *     is so you can have newlines in the output.
 *
 * Note that if the <id> is "-", it means the id couldn't be obtained from
 * the command.
 *
 * Note that <id>, <return code>, <dev>, <cid> and <devidx> are decimal
 * numbers.  All other values are hexadecimal.
 *
 * With the lan.conf set up as it is now, there are 3 IPMI devices.
 * If you load ipmi_si first, then a BT interface connected to BMC 0
 * (the one simulated in ipmi_sim) is ipmi0, a KCS interface connected
 * to BMC 1 (one simulated inside qemu) is ipmi1.  Then if you load
 * ipmi_ssif, ipmi2 will be connected to BMC 0 as a second interface
 * to the same BMC.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <linux/ipmi.h>
#include <gensio/gensio.h>
#include <gensio/gensio_list.h>
#include <gensio/argvutils.h>

static void
do_vlog(struct gensio_os_funcs *f, enum gensio_log_levels level,
	const char *log, va_list args)
{
    fprintf(stderr, "gensio %s log: ", gensio_log_level_to_str(level));
    vfprintf(stderr, log, args);
    fprintf(stderr, "\n");
}

struct sendbuf {
    struct gensio_link link;
    gensiods len;
    gensiods pos;
    unsigned char *data;
};

struct ipmiinfo {
    int fd;
    struct gensio_iod *iod;
    bool closing;
    struct accinfo *ai;
    struct gensio_waiter *close_waiter;
    unsigned int devidx;
    long next_iid;
    struct gensio_list cmd_rsps;
};
#define NUM_IPMI_INFO 10

struct ioinfo {
    struct accinfo *ai;
    struct gensio *io;
    struct gensio_link link;

    char inbuf[1024]; /* Holds read data */
    unsigned int inbuf_len;

    /* List of struct sendbuf to write. */
    struct gensio_list writelist;

    bool closing; /* We have started a close */
    bool close_on_write;
};

struct accinfo {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
    struct gensio_accepter *acc;
    struct gensio_list ios; /* List of ioinfo */
    struct ipmiinfo *ipis; /* Array of IPMI device opens. */
    bool shutting_down;
};

struct cmd_rsp_wait {
    struct gensio_link link;

    /* IPMI_RESPONSE_RECV_TYPE or IPMI_RESPONSE_RESPONSE_TYPE. */
    int expected_type;

    long msgid;

    unsigned long long id;

    struct ioinfo *ii;
};

static void
shutdown_done(struct gensio_accepter *acc, void *shutdown_data)
{
    struct accinfo *ai = shutdown_data;

    gensio_os_funcs_wake(ai->o, ai->waiter);
}

static void
check_shutdown(struct accinfo *ai)
{
    int rv;

    if (!ai->shutting_down || !gensio_list_empty(&ai->ios))
	return;

    rv = gensio_acc_shutdown(ai->acc, shutdown_done, ai);
    if (rv) {
	fprintf(stderr, "Error shutting down accepter: %s\n",
		gensio_err_to_str(rv));
	shutdown_done(NULL, ai);
    }
}

static void
close_done(struct gensio *io, void *close_data)
{
    struct ioinfo *ii = close_data;
    struct accinfo *ai = ii->ai;

    gensio_free(io);
    gensio_list_rm(&ai->ios, &ii->link);
    free(ii);
    check_shutdown(ai);
}

static struct sendbuf *
sendbuf_dup(struct gensio_os_funcs *o, const struct sendbuf *s)
{
    struct sendbuf *s2 =
	gensio_os_funcs_zalloc(o, sizeof(struct sendbuf) + s->len + 1);

    if (s2) {
	s2->len = s->len;
	s2->data = ((unsigned char *) s2) + sizeof(*s2);
	memcpy(s2->data, s->data, s2->len);
    }
    return s2;
}

static struct sendbuf *
al_vsprintf(struct gensio_os_funcs *o, char *str, va_list ap)
{
    struct sendbuf *s;
    va_list ap2;
    size_t len;
    char dummy;

    va_copy(ap2, ap);
    len = vsnprintf(&dummy, 1, str, ap);
    s = gensio_os_funcs_zalloc(o, sizeof(struct sendbuf) + len + 1);
    if (!s)
	return NULL;
    s->len = len + 1;
    s->pos = 0;
    s->data = ((unsigned char *) s) + sizeof(*s);
    vsnprintf((char *) s->data, len + 1, str, ap2);
    va_end(ap2);
    s->data[len] = '\0';

    return s;
}

struct data_sg {
    const char *header;
    unsigned int len;
    unsigned char *data;
};

static struct sendbuf *
al_vsprintf_data(struct gensio_os_funcs *o,
		 const struct data_sg data[], unsigned int dlen,
		 const char *str, va_list ap)
{
    struct sendbuf *s;
    va_list ap2;
    size_t len;
    char dummy;
    unsigned int i, j;

    va_copy(ap2, ap);
    len = vsnprintf(&dummy, 1, str, ap);
    for (i = 0; i < dlen; i++) {
	if (data[i].header)
	    len += 1 + strlen(data[i].header);
	len += 3 * data[i].len;
    }
    s = gensio_os_funcs_zalloc(o, sizeof(struct sendbuf) + len + 1);
    if (!s)
	return NULL;
    s->len = len + 1;
    s->pos = 0;
    s->data = ((unsigned char *) s) + sizeof(*s);
    len = vsnprintf((char *) s->data, len + 1, str, ap2);
    va_end(ap2);
    for (i = 0; i < dlen; i++) {
	if (data[i].header)
	    len += sprintf((char *) s->data + len, " %s", data[i].header);
	for (j = 0; j < data[i].len; j++)
	    len += sprintf((char *) s->data + len, " %2.2x", data[i].data[j]);
    }
    s->data[len] = '\0';

    return s;
}

static struct sendbuf *
al_sprintf_data(struct gensio_os_funcs *o,
		const struct data_sg *data, unsigned int dlen,
		const char *str, ...)
{
    va_list ap;
    struct sendbuf *s;

    va_start(ap, str);
    s = al_vsprintf_data(o, data, dlen, str, ap);
    va_end(ap);
    return s;
}

__attribute__ ((__format__ (__printf__, 2, 3)))
static void
add_output_buf(struct ioinfo *ii, char *str, ...)
{
    va_list ap;
    struct sendbuf *s;

    va_start(ap, str);
    s = al_vsprintf(ii->ai->o, str, ap);
    va_end(ap);

    gensio_list_add_tail(&ii->writelist, &s->link);
    gensio_set_write_callback_enable(ii->io, true);
}

__attribute__ ((__format__ (__printf__, 2, 3)))
static void
add_output_msgrsp(struct ioinfo *ii, char *str, ...)
{
    va_list ap;
    struct sendbuf *s;

    va_start(ap, str);
    s = al_vsprintf(ii->ai->o, str, ap);
    va_end(ap);

    gensio_list_add_tail(&ii->writelist, &s->link);
    gensio_set_write_callback_enable(ii->io, true);
}

static void
append_output_list_all(struct accinfo *ai, struct sendbuf *s)
{
    struct gensio_link *l;
    struct sendbuf *s2;

    gensio_list_for_each(&ai->ios, l) {
	struct ioinfo *ii = gensio_container_of(l, struct ioinfo, link);

	if (l == gensio_list_last(&ai->ios))
	    s2 = s;
	else
	    s2 = sendbuf_dup(ai->o, s);
	if (s2) {
	    gensio_list_add_tail(&ii->writelist, &s2->link);
	    gensio_set_write_callback_enable(ii->io, true);
	}
    }
}

__attribute__ ((__format__ (__printf__, 2, 3)))
static void
add_output_buf_all(struct accinfo *ai, char *str, ...)
{
    va_list ap;
    struct sendbuf *s;

    if (gensio_list_empty(&ai->ios))
	return;

    va_start(ap, str);
    s = al_vsprintf(ai->o, str, ap);
    va_end(ap);
    if (!s)
	return;

    append_output_list_all(ai, s);
}

static void
add_output_buf_event_all(struct accinfo *ai, unsigned int devidx,
			 struct ipmi_msg *msg)
{
    struct sendbuf *s;
    struct data_sg sg = { .header = NULL,
			  .len = msg->data_len, .data = msg->data };

    if (gensio_list_empty(&ai->ios))
	return;

    s = al_sprintf_data(ai->o, &sg, 1, "Event %d", devidx);
    if (s)
	append_output_list_all(ai, s);
}

static struct sendbuf *
format_output_buf_msg(struct gensio_os_funcs *o,
		      unsigned char *addr, struct ipmi_msg *msg,
		      const char *str, va_list ap)
{
    struct data_sg sg[2];
    unsigned char addr_bytes[IPMI_MAX_ADDR_SIZE];
    struct ipmi_addr *iaddr = (struct ipmi_addr *) addr;

    sg[0].data = addr_bytes;
    switch (iaddr->addr_type) {
    case IPMI_SYSTEM_INTERFACE_ADDR_TYPE: {
	struct ipmi_system_interface_addr *a =
	    (struct ipmi_system_interface_addr *) iaddr;

	sg[0].header = "si";
	sg[0].len = 2;
	sg[0].data[0] = a->channel;
	sg[0].data[1] = a->lun;
	break;
    }

    case IPMI_IPMB_ADDR_TYPE: {
	struct ipmi_ipmb_addr *a = (struct ipmi_ipmb_addr *) iaddr;

	sg[0].header = "ipmb";
	sg[0].len = 3;
	sg[0].data[0] = a->channel;
	sg[0].data[1] = a->slave_addr;
	sg[0].data[2] = a->lun;
	break;
    }

    case IPMI_LAN_ADDR_TYPE: {
	struct ipmi_lan_addr *a = (struct ipmi_lan_addr *) iaddr;

	sg[0].header = "lan";
	sg[0].len = 6;
	sg[0].data[0] = a->channel;
	sg[0].data[1] = a->privilege;
	sg[0].data[2] = a->session_handle;
	sg[0].data[3] = a->remote_SWID;
	sg[0].data[4] = a->local_SWID;
	sg[0].data[5] = a->lun;
	break;
    }

    default:
	return NULL;
    }

    sg[0].data[sg[0].len++] = msg->netfn;
    sg[0].data[sg[0].len++] = msg->cmd;
    sg[1].header = NULL;
    sg[1].len = msg->data_len;
    sg[1].data = msg->data;

    return al_vsprintf_data(o, sg, 2, str, ap);
}

static void
add_output_buf_msg_all(struct accinfo *ai,
		       unsigned char *addr, struct ipmi_msg *msg,
		       const char *str, ...)
{
    struct sendbuf *s;
    va_list ap;

    if (gensio_list_empty(&ai->ios))
	return;

    va_start(ap, str);
    s = format_output_buf_msg(ai->o, addr, msg, str, ap);
    va_end(ap);
    if (s)
	append_output_list_all(ai, s);
}

static void
add_output_buf_msg(struct ioinfo *ii,
		   unsigned char *addr, struct ipmi_msg *msg,
		   const char *str, ...)
{
    struct sendbuf *s;
    va_list ap;

    va_start(ap, str);
    s = format_output_buf_msg(ii->ai->o, addr, msg, str, ap);
    va_end(ap);
    if (s) {
	gensio_list_add_tail(&ii->writelist, &s->link);
	gensio_set_write_callback_enable(ii->io, true);
    }
}

static void
start_ioinfo_close(struct ioinfo *ii)
{
    int rv;
    struct accinfo *ai = ii->ai;
    unsigned int i;

    /* Nuke any responses that we are waiting for. */
    for (i = 0; i < NUM_IPMI_INFO; i++) {
	struct gensio_link *l, *l2;

	if (ai->ipis[i].fd == -1)
	    continue;
	gensio_list_for_each_safe(&ai->ipis[i].cmd_rsps, l, l2) {
	    struct cmd_rsp_wait *crw =
		gensio_container_of(l, struct cmd_rsp_wait, link);

	    if (crw->ii == ii) {
		gensio_list_rm(&ai->ipis[i].cmd_rsps, &crw->link);
		gensio_os_funcs_zfree(ai->o, crw);
	    }
	}
    }

    ii->closing = true;
    rv = gensio_close(ii->io, close_done, ii);
    if (rv) {
	/* Should be impossible, but just in case... */
	fprintf(stderr, "Error closing io: %s\n", gensio_err_to_str(rv));
	close_done(ii->io, ii);
    }
}

static bool
get_num(const char *v, unsigned int *onum)
{
    unsigned int num;
    char *end;

    if (!v)
	return false;

    num = strtoul(v, &end, 0);
    if (v[0] == '\0' || *end != '\0')
	return false;
    *onum = num;
    return true;
}

static bool
get_hnum(const char *v, unsigned int *onum)
{
    unsigned int num;
    char *end;

    if (!v)
	return false;

    num = strtoul(v, &end, 16);
    if (v[0] == '\0' || *end != '\0')
	return false;
    *onum = num;
    return true;
}

static int
run_cmd(struct ioinfo *ii, unsigned long long id, const char *loadcmdstr)
{
    struct gensio_os_funcs *o = ii->ai->o;
    struct gensio *io;
    int rv, rc;
    gensiods count, pos;
    char buf[1024], ibuf[8], dummy[128];
    gensio_time timeout = { 10, 0 };

    rv = str_to_gensio(loadcmdstr, o, NULL, NULL, &io);
    if (rv) {
	add_output_buf(ii, "Done %llu Unable to create gensio %s: %s", id,
		       loadcmdstr, gensio_err_to_str(rv));
	return 0;
    }

    rv = gensio_open_s(io);
    if (rv) {
	add_output_buf(ii, "Done %llu Unable to open gensio %s: %s", id,
		       loadcmdstr, gensio_err_to_str(rv));
	goto out;
    }

    rv = gensio_set_sync(io);
    if (rv) {
	add_output_buf(ii, "Done %llu Unable to set sync for gensio %s: %s", id,
		       loadcmdstr, gensio_err_to_str(rv));
	goto out;
    }

    rv = 0;
    pos = 0;
    while (rv == 0) {
	if (pos < sizeof(buf) - 1) {
	    rv = gensio_read_s(io, &count, buf + pos, sizeof(buf) - pos,
			       &timeout);
	    if (!rv)
		pos += count;
	} else {
	    /* Throw away data after the buf size. */
	    rv = gensio_read_s(io, NULL, dummy, sizeof(dummy), &timeout);
	}
    }

    rv = GE_INPROGRESS;
    while (rv == GE_INPROGRESS) {
	count = sizeof(ibuf);
	rv = gensio_control(io, 0, GENSIO_CONTROL_GET, GENSIO_CONTROL_WAIT_TASK,
			    ibuf, &count);
    }
    if (rv) {
	add_output_buf(ii, "Done %llu Unable to wait on gensio %s: %s", id,
		       loadcmdstr, gensio_err_to_str(rv));
	goto out;
    }
    rc = atoi(ibuf);

    rv = gensio_close_s(io);
    if (rv) {
	add_output_buf(ii, "Done %llu Unable to close gensio %s: %s", id,
		       loadcmdstr, gensio_err_to_str(rv));
	goto out;
    }

    if (rc) {
	buf[pos - 1] = '\0';
	add_output_buf(ii, "Done %llu Error executing command %s: %s %s", id,
		       loadcmdstr, ibuf, buf);
	rv = 1;
    } else {
	rv = 0;
    }

 out:
    gensio_free(io);
    return rv;
}

static void
do_close(struct ipmiinfo *ipi)
{
    struct gensio_os_funcs *o = ipi->ai->o;
    struct gensio_link *l, *l2;

    ipi->closing = true;
    o->clear_fd_handlers(ipi->iod);

    gensio_os_funcs_wait(o, ipi->close_waiter, 1, NULL);
    o->close(&ipi->iod);
    ipi->fd = -1;
    ipi->closing = false;

    /* Return error responses for any pending operations. */
    gensio_list_for_each_safe(&ipi->cmd_rsps, l, l2) {
	struct cmd_rsp_wait *crw =
	    gensio_container_of(l, struct cmd_rsp_wait, link);

	gensio_list_rm(&ipi->cmd_rsps, &crw->link);
	if (crw->expected_type == IPMI_RESPONSE_RECV_TYPE)
	    add_output_buf(crw->ii, "Response %llu %d err IPMI device closed",
			   crw->id, ipi->devidx);
	else
	    add_output_buf(crw->ii,
			   "ResponseResponse %llu %d err IPMI device closed",
			   crw->id, ipi->devidx);
	gensio_os_funcs_zfree(o, crw);
    }
}

struct cmd_rsp_wait *
find_cmd_rsp(struct ipmiinfo *ipi, struct ipmi_recv *recv)
{
    struct gensio_link *l;

    gensio_list_for_each(&ipi->cmd_rsps, l) {
	struct cmd_rsp_wait *crw = gensio_container_of(l, struct cmd_rsp_wait,
						       link);

	if (crw->msgid == recv->msgid &&
		crw->expected_type == recv->recv_type) {
	    gensio_list_rm(&ipi->cmd_rsps, &crw->link);
	    return crw;
	}
    }
    return NULL;
}

static void
ipmi_dev_read_ready(struct gensio_iod *iod, void *cb_data)
{
    struct ipmiinfo *ipi = cb_data;
    struct ipmi_addr addr;
    unsigned char data[256];
    struct ipmi_recv recv = { .addr = (unsigned char *) &addr,
			      .addr_len = sizeof(addr),
			      .msg.data = data,
			      .msg.data_len = sizeof(data) };
    struct cmd_rsp_wait *crw;
    ssize_t rv;

 retry:
    rv = ioctl(ipi->fd, IPMICTL_RECEIVE_MSG, &recv);
    if (rv == -1) {
	if (errno == EINTR)
	    goto retry;
	if (errno == EAGAIN)
	    return;
	/* Driver has issues, close it. */
	do_close(ipi);
	add_output_buf_all(ipi->ai, "Closed %d", ipi->devidx);
	return;
    }

    switch (recv.recv_type) {
    case IPMI_RESPONSE_RECV_TYPE:
	crw = find_cmd_rsp(ipi, &recv);
	if (!crw)
	    return;
	add_output_buf_msg(crw->ii, recv.addr, &recv.msg,
			   "Response %llu %d", crw->id, ipi->devidx);
	gensio_os_funcs_zfree(ipi->ai->o, crw);
	break;

    case IPMI_RESPONSE_RESPONSE_TYPE:
	crw = find_cmd_rsp(ipi, &recv);
	if (!crw)
	    return;
	if (recv.msg.data[0])
	    add_output_buf(crw->ii, "ResponseResponse %llu %d %2.2x",
			   crw->id, ipi->devidx, recv.msg.data[0]);
	else
	    add_output_buf(crw->ii, "ResponseResponse %llu %d",
			   crw->id, ipi->devidx);
	gensio_os_funcs_zfree(ipi->ai->o, crw);
	break;

    case IPMI_ASYNC_EVENT_RECV_TYPE:
	add_output_buf_event_all(ipi->ai, ipi->devidx, &recv.msg);
	break;

    case IPMI_CMD_RECV_TYPE:
	add_output_buf_msg_all(ipi->ai, recv.addr, &recv.msg,
			       "Command %lld %d",
			       (long long) recv.msgid, ipi->devidx);
	break;

    default:
	return;
    }
}

static void
ipmi_dev_cleared(struct gensio_iod *iod, void *cb_data)
{
    struct ipmiinfo *ipi = cb_data;

    gensio_os_funcs_wake(ipi->ai->o, ipi->close_waiter);
}

static void
handle_open(struct ioinfo *ii, unsigned long long id, const char **tokens)
{
    struct ipmiinfo *ipi = ii->ai->ipis;
    struct gensio_os_funcs *o = ii->ai->o;
    unsigned int devidx, devnum;
    char devstr[128];
    int rv;

    if (!get_num(tokens[0], &devidx) || devidx >= NUM_IPMI_INFO) {
	add_output_buf(ii, "Done %llu invalid devidx: %s", id, tokens[0]);
	return;
    }

    if (ipi[devidx].fd != -1) {
	add_output_buf(ii, "Done %llu devidx %s already in use", id, tokens[0]);
	return;
    }

    if (!get_num(tokens[1], &devnum) || devnum >= NUM_IPMI_INFO) {
	add_output_buf(ii, "Done %llu invalid dev: %s", id, tokens[1]);
	return;
    }

    snprintf(devstr, sizeof(devstr), "/dev/ipmi%u", devnum);

    ipi[devidx].fd = open(devstr, O_RDWR | O_NONBLOCK);
    if (ipi[devidx].fd == -1) {
	add_output_buf(ii, "Done %llu Unable to open dev %s: %s", id,
		       devstr, strerror(errno));
	return;
    }

    rv = o->add_iod(o, GENSIO_IOD_DEV, ipi[devidx].fd, &ipi[devidx].iod);
    if (rv) {
	add_output_buf(ii, "Done %llu Unable to set iod %s: %s", id,
		       devstr, gensio_err_to_str(rv));
	close(ipi[devidx].fd);
	ipi[devidx].fd = -1;
	return;
    }

    rv = o->set_fd_handlers(ipi[devidx].iod, &ipi[devidx], ipmi_dev_read_ready,
			    NULL, NULL, ipmi_dev_cleared);
    if (rv) {
	add_output_buf(ii, "Done %llu Unable to setup fd %s: %s", id,
		       devstr, gensio_err_to_str(rv));
	o->close(&ipi[devidx].iod);
	ipi[devidx].fd = -1;
	return;
    }

    add_output_buf(ii, "Done %llu", id);

    o->set_read_handler(ipi[devidx].iod, true);
}

static void
handle_close(struct ioinfo *ii, unsigned long long id, const char **tokens)
{
    struct ipmiinfo *ipi = ii->ai->ipis;
    unsigned int devidx;

    if (!get_num(tokens[0], &devidx) || devidx >= NUM_IPMI_INFO) {
	add_output_buf(ii, "Done %llu invalid dev: %s", id, tokens[0]);
	return;
    }

    if (ipi[devidx].fd == -1 || ipi[devidx].closing) {
	add_output_buf(ii, "Done %llu id %s not open", id, tokens[0]);
	return;
    }

    do_close(&ipi[devidx]);
    add_output_buf(ii, "Done %llu", id);
}

static void
handle_panic(struct ioinfo *iic, unsigned long long id, const char **tokens)
{
    struct accinfo *ai = iic->ai;
    gensio_time timeout = {1, 0};
    struct gensio_link *l;
    int fd;
    bool any_waiting = true;

    add_output_buf_all(ai, "Panic %lld", id);
    while (any_waiting) {
	any_waiting = false;
	gensio_list_for_each(&ai->ios, l) {
	    struct ioinfo *ii = gensio_container_of(l, struct ioinfo, link);

	    if (!gensio_list_empty(&ii->writelist)) {
		any_waiting = true;
		break;
	    }
	}
	timeout.secs = 1;
	timeout.nsecs = 0;
	gensio_os_funcs_service(ai->o, &timeout);
    }
    timeout.secs = 1;
    timeout.nsecs = 0;
    gensio_os_funcs_wait(ai->o, ai->waiter, 1, &timeout);
    fd = open("/proc/sysrq-trigger", O_WRONLY);
    if (fd == -1) {
	fprintf(stderr, "Done %lld Unable to open /proc/sysrq-trigger: %s\n",
		id, strerror(errno));
	exit(1);
    }
    write(fd, "c\n", 2);
    close(fd);
    exit(0);
}

static void
handle_load(struct ioinfo *ii, unsigned long long id, const char **tokens)
{
    char loadcmdstr[128];
    unsigned int i;

    if (!tokens[0]) {
	add_output_buf(ii, "Done %llu No module given", id);
	return;
    }

    for (i = 0; tokens[i]; i++) {
	snprintf(loadcmdstr, sizeof(loadcmdstr),
		 "stdio(stderr-to-stdout),insmod %s.ko", tokens[i]);
	if (run_cmd(ii, id, loadcmdstr))
	    goto out;
    }
    add_output_buf(ii, "Done %llu", id);
 out:
    return;
}

static void
handle_unload(struct ioinfo *ii, unsigned long long id, const char **tokens)
{
    char loadcmdstr[128];
    unsigned int i;

    if (!tokens[0]) {
	add_output_buf(ii, "Done %llu No module given", id);
	return;
    }

    for (i = 0; tokens[i]; i++) {
	snprintf(loadcmdstr, sizeof(loadcmdstr),
		 "stdio(stderr-to-stdout),rmmod %s", tokens[i]);
	if (run_cmd(ii, id, loadcmdstr))
	    goto out;
    }
    add_output_buf(ii, "Done %llu", id);
 out:
    return;
}

static void
handle_cycle(struct ioinfo *ii, unsigned long long id, const char **tokens)
{
    char loadcmdstr[128];
    unsigned int i, j, count;

    if (!tokens[0]) {
	add_output_buf(ii, "Done %llu No count given", id);
	return;
    }
    if (!tokens[1]) {
	add_output_buf(ii, "Done %llu No module given", id);
	return;
    }
    if (!get_num(tokens[0], &count)) {
	add_output_buf(ii, "Done %llu invalid count: %s", id, tokens[0]);
	return;
    }

    for (i = 0; i < count; i++) {
	for (j = 1; tokens[j]; j++) {
	    snprintf(loadcmdstr, sizeof(loadcmdstr),
		     "stdio(stderr-to-stdout),insmod %s.ko", tokens[j]);
	    if (run_cmd(ii, id, loadcmdstr))
		return;
	}
	for (j--; j > 0; j--) {
	    snprintf(loadcmdstr, sizeof(loadcmdstr),
		     "stdio(stderr-to-stdout),rmmod %s", tokens[j]);
	    if (run_cmd(ii, id, loadcmdstr))
		return;
	}
    }
    add_output_buf(ii, "Done %llu", id);
}

static bool
parse_addrs(struct ioinfo *ii, unsigned long long id, const char **tokens,
	    struct ipmi_addr *addr, unsigned int *addr_len, unsigned int *pos)
{
    unsigned int num;

    tokens += *pos;

    if (!tokens[0])
	add_output_buf(ii, "Done %llu No address given", id);
	
    if (strcmp(tokens[0], "si") == 0) {
	struct ipmi_system_interface_addr *a =
	    (struct ipmi_system_interface_addr *) addr;

	a->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	if (!get_hnum(tokens[1], &num) || num >= IPMI_NUM_CHANNELS) {
	    add_output_buf(ii, "Done %llu Invalid channel for si address", id);
	    return false;
	}
	a->channel = num;
	if (!get_hnum(tokens[2], &num) || num > 3) {
	    add_output_buf(ii, "Done %llu Invalid LUN for si address", id);
	    return false;
	}
	a->lun = num;
	*addr_len = sizeof(*a);
	*pos += 3;
    } else if (strcmp(tokens[0], "ipmb") == 0) {
	struct ipmi_ipmb_addr *a = (struct ipmi_ipmb_addr *) addr;

	a->addr_type = IPMI_IPMB_ADDR_TYPE;
	if (!get_hnum(tokens[1], &num) || num >= IPMI_NUM_CHANNELS) {
	    add_output_buf(ii, "Done %llu Invalid channel for ipmb address",
			   id);
	    return false;
	}
	a->channel = num;
	if (!get_hnum(tokens[2], &num) || num > 255) {
	    add_output_buf(ii, "Done %llu Invalid ipmb for ipmb address", id);
	    return false;
	}
	a->slave_addr = num;
	if (!get_hnum(tokens[3], &num) || num > 3) {
	    add_output_buf(ii, "Done %llu Invalid LUN for ipmb address", id);
	    return false;
	}
	a->lun = num;
	*addr_len = sizeof(*a);
	*pos += 4;
    } else if (strcmp(tokens[0], "lan") == 0) {
	struct ipmi_lan_addr *a = (struct ipmi_lan_addr *) addr;

	a->addr_type = IPMI_LAN_ADDR_TYPE;
	if (!get_hnum(tokens[1], &num) || num >= IPMI_NUM_CHANNELS) {
	    add_output_buf(ii, "Done %llu Invalid channel for lan address",
			   id);
	    return false;
	}
	a->channel = num;
	if (!get_hnum(tokens[2], &num) || num > 5) {
	    add_output_buf(ii, "Done %llu Invalid privilege for lan address",
			   id);
	    return false;
	}
	a->privilege = num;
	if (!get_hnum(tokens[3], &num) || num > 255) {
	    add_output_buf(ii, "Done %llu Invalid privilege for lan address",
			   id);
	    return false;
	}
	a->session_handle = num;
	if (!get_hnum(tokens[4], &num) || num > 255) {
	    add_output_buf(ii, "Done %llu Invalid rSWID for lan address",
			   id);
	    return false;
	}
	a->remote_SWID = num;
	if (!get_hnum(tokens[5], &num) || num > 255) {
	    add_output_buf(ii, "Done %llu Invalid lSWID for lan address",
			   id);
	    return false;
	}
	a->local_SWID = num;
	if (!get_hnum(tokens[6], &num) || num > 3) {
	    add_output_buf(ii, "Done %llu Invalid LUN for lan address", id);
	    return false;
	}
	a->lun = num;
	*addr_len = sizeof(*a);
	*pos += 7;
    } else {
	add_output_buf(ii, "Done %llu Unknown address type: %s", id, tokens[0]);
	return false;
    }
    return true;
}

static bool
parse_data(struct ioinfo *ii, unsigned long long id, const char **tokens,
	   unsigned char *data, unsigned short *data_len,
	   unsigned short max_data_len, unsigned int *pos)
{
    unsigned int i = 0;
    unsigned int num;

    tokens += *pos;

    for(i = 0; tokens[i]; i++) {
	if (i >= max_data_len) {
	    add_output_buf(ii, "Done %llu Message too long", id);
	    return false;
	}
	if (!get_hnum(tokens[i], &num) || num > 255) {
	    add_output_buf(ii, "Done %llu Invalid data item %d: %s", id, i,
			   tokens[i]);
	    return false;
	}
	data[i] = num;
    }
    *pos += i;
    *data_len = i;
    return true;
}

static void
handle_command(struct ioinfo *ii, unsigned long long id, const char **tokens)
{
    unsigned int devidx;
    struct ipmi_addr addr;
    unsigned char data[256];
    unsigned int i, num;
    struct ipmi_req req;
    struct cmd_rsp_wait *crw;
    struct ipmiinfo *ipi;
    int rv;

    memset(&addr, 0, sizeof(addr));
    memset(&req, 0, sizeof(req));
    req.addr = (unsigned char *) &addr;
    req.msg.data = data;

    if (!get_num(tokens[0], &devidx) || devidx >= NUM_IPMI_INFO) {
	add_output_buf(ii, "Done %llu invalid devidx: %s", id, tokens[0]);
	return;
    }
    ipi = &ii->ai->ipis[devidx];
    if (ipi->fd == -1) {
	add_output_buf(ii, "Done %llu dev not open", id);
	return;
    }

    i = 1;
    if (!parse_addrs(ii, id, tokens, &addr, &req.addr_len, &i))
	return;
    if (!get_hnum(tokens[i], &num) || num >= 255) {
	add_output_buf(ii, "Done %llu invalid netfn: %s", id, tokens[i]);
	return;
    }
    i++;
    req.msg.netfn = num;
    if (!get_hnum(tokens[i], &num) || num >= 255) {
	add_output_buf(ii, "Done %llu invalid cmd: %s", id, tokens[i]);
	return;
    }
    req.msg.cmd = num;
    i++;
    if (!parse_data(ii, id, tokens,
		    req.msg.data, &req.msg.data_len, sizeof(data), &i))
	return;

    req.msgid = ipi->next_iid++;
    crw = gensio_os_funcs_zalloc(ii->ai->o, sizeof(*crw));
    if (!crw) {
	add_output_buf(ii, "Done %llu Out of memory", id);
	return;
    }
    crw->expected_type = IPMI_RESPONSE_RECV_TYPE;
    crw->msgid = req.msgid;
    crw->id = id;
    crw->ii = ii;

    gensio_list_add_tail(&ipi->cmd_rsps, &crw->link);
    rv = ioctl(ipi->fd, IPMICTL_SEND_COMMAND, &req);
    if (rv) {
	gensio_list_rm(&ipi->cmd_rsps, &crw->link);
	add_output_buf(ii, "Done %llu Send error: %s", id, strerror(errno));
	gensio_os_funcs_zfree(ii->ai->o, crw);
    } else {
	add_output_buf(ii, "Done %llu", id);
    }
}

static void
handle_response(struct ioinfo *ii, unsigned long long id, const char **tokens)
{
    unsigned int devidx;
    struct ipmi_addr addr;
    unsigned char data[256];
    unsigned int i, num;
    long long cid;
    struct ipmi_req req;
    struct cmd_rsp_wait *crw;
    struct ipmiinfo *ipi;
    char *end;
    int rv;

    memset(&addr, 0, sizeof(addr));
    memset(&req, 0, sizeof(req));
    req.addr = (unsigned char *) &addr;
    req.msg.data = data;

    if (!get_num(tokens[0], &devidx) || devidx >= NUM_IPMI_INFO) {
	add_output_buf(ii, "Done %llu invalid devidx: %s", id, tokens[0]);
	return;
    }
    ipi = &ii->ai->ipis[devidx];
    if (ipi->fd == -1) {
	add_output_buf(ii, "Done %llu devidx not open", id);
	return;
    }

    cid = strtoll(tokens[1], &end, 0);
    if (tokens[1][0] == '\0' || *end != '\0') {
	/* Not a valid number. */
	add_output_buf(ii, "Done - Invalid cid");
	return;
    }

    i = 2;
    if (!parse_addrs(ii, id, tokens, &addr, &req.addr_len, &i))
	return;
    if (!get_hnum(tokens[i], &num) || num >= 255) {
	add_output_buf(ii, "Done %llu invalid netfn: %s", id, tokens[i]);
	return;
    }
    i++;
    req.msg.netfn = num;
    if (!get_hnum(tokens[i], &num) || num >= 255) {
	add_output_buf(ii, "Done %llu invalid cmd: %s", id, tokens[i]);
	return;
    }
    req.msg.cmd = num;
    i++;
    if (!parse_data(ii, id, tokens,
		    req.msg.data, &req.msg.data_len, sizeof(data), &i))
	return;

    req.msgid = cid;
    crw = gensio_os_funcs_zalloc(ii->ai->o, sizeof(*crw));
    if (!crw) {
	add_output_buf(ii, "Done %llu Out of memory", id);
	return;
    }
    crw->expected_type = IPMI_RESPONSE_RESPONSE_TYPE;
    crw->msgid = req.msgid;
    crw->id = id;
    crw->ii = ii;

    gensio_list_add_tail(&ipi->cmd_rsps, &crw->link);
    rv = ioctl(ipi->fd, IPMICTL_SEND_COMMAND, &req);
    if (rv) {
	gensio_list_rm(&ipi->cmd_rsps, &crw->link);
	add_output_buf(ii, "Done %llu Send error: %s", id, strerror(errno));
	gensio_os_funcs_zfree(ii->ai->o, crw);
    } else {
	add_output_buf(ii, "Done %llu", id);
    }
}

static void
handle_register(struct ioinfo *ii, unsigned long long id, const char **tokens)
{
    struct ipmiinfo *ipi;
    unsigned int devidx, num;
    struct ipmi_cmdspec_chans cs;
    int rv;

    if (!get_num(tokens[0], &devidx) || devidx >= NUM_IPMI_INFO) {
	add_output_buf(ii, "Done %llu invalid devidx: %s", id, tokens[0]);
	return;
    }
    ipi = &ii->ai->ipis[devidx];
    if (ipi->fd == -1) {
	add_output_buf(ii, "Done %llu dev not open", id);
	return;
    }

    if (!get_num(tokens[1], &num) || num > 255) {
	add_output_buf(ii, "Done %llu invalid netfn: %s", id, tokens[1]);
	return;
    }
    cs.netfn = num;

    if (!get_num(tokens[2], &num) || num > 255) {
	add_output_buf(ii, "Done %llu invalid cmd: %s", id, tokens[2]);
	return;
    }
    cs.cmd = num;

    cs.chans = IPMI_CHAN_ALL;
    if (tokens[3]) {
	if (!get_hnum(tokens[2], &num)) {
	    add_output_buf(ii, "Done %llu invalid channels: %s", id, tokens[3]);
	    return;
	}
	cs.chans = num;
    }

    rv = ioctl(ipi->fd, IPMICTL_REGISTER_FOR_CMD_CHANS, &cs);
    if (rv == -1) {
	add_output_buf(ii, "Done %llu Error: %s", id, strerror(errno));
	return;
    }
    add_output_buf(ii, "Done %llu", id);
}

static void
handle_unregister(struct ioinfo *ii, unsigned long long id, const char **tokens)
{
    struct ipmiinfo *ipi;
    unsigned int devidx, num;
    struct ipmi_cmdspec_chans cs;
    int rv;

    if (!get_num(tokens[0], &devidx) || devidx >= NUM_IPMI_INFO) {
	add_output_buf(ii, "Done %llu invalid devidx: %s", id, tokens[0]);
	return;
    }
    ipi = &ii->ai->ipis[devidx];
    if (ipi->fd == -1) {
	add_output_buf(ii, "Done %llu dev not open", id);
	return;
    }

    if (!get_num(tokens[1], &num) || num > 255) {
	add_output_buf(ii, "Done %llu invalid netfn: %s", id, tokens[1]);
	return;
    }
    cs.netfn = num;

    if (!get_num(tokens[2], &num) || num > 255) {
	add_output_buf(ii, "Done %llu invalid cmd: %s", id, tokens[2]);
	return;
    }
    cs.cmd = num;

    cs.chans = IPMI_CHAN_ALL;
    if (tokens[3]) {
	if (!get_hnum(tokens[2], &num)) {
	    add_output_buf(ii, "Done %llu invalid channels: %s", id, tokens[3]);
	    return;
	}
	cs.chans = num;
    }

    rv = ioctl(ipi->fd, IPMICTL_UNREGISTER_FOR_CMD_CHANS, &cs);
    if (rv == -1) {
	add_output_buf(ii, "Done %llu Error: %s", id, strerror(errno));
	return;
    }
    add_output_buf(ii, "Done %llu", id);
}

static void
handle_evenable(struct ioinfo *ii, unsigned long long id, const char **tokens)
{
    struct ipmiinfo *ipi;
    unsigned int devidx, enable;
    int rv;

    if (!get_num(tokens[0], &devidx) || devidx >= NUM_IPMI_INFO) {
	add_output_buf(ii, "Done %llu invalid devidx: %s", id, tokens[0]);
	return;
    }
    ipi = &ii->ai->ipis[devidx];
    if (ipi->fd == -1) {
	add_output_buf(ii, "Done %llu dev not open", id);
	return;
    }

    if (!get_num(tokens[1], &enable)) {
	add_output_buf(ii, "Done %llu invalid enable: %s", id, tokens[1]);
	return;
    }

    rv = ioctl(ipi->fd, IPMICTL_SET_GETS_EVENTS_CMD, &enable);
    if (rv == -1) {
	add_output_buf(ii, "Done %llu Error: %s", id, strerror(errno));
	return;
    }
    add_output_buf(ii, "Done %llu", id);
}

static void
handle_runcmd(struct ioinfo *ii, unsigned long long id, const char **tokens)
{
    int rv, rc;
    struct gensio *cmd;
    gensio_time timeout = { 10, 0 };
    gensiods count, pos;
    char buf[1024], ibuf[8], dummy[128];

    if (!tokens[0]) {
	add_output_buf(ii, "Done %llu No command given", id);
	return;
    }

    rv = str_to_gensio("stdio(stderr-to-stdout)", ii->ai->o, NULL, NULL, &cmd);
    if (rv) {
	add_output_buf(ii, "Done %llu Unable to allocate gensio: %s", id,
		       gensio_err_to_str(rv));
	return;
    }

    rv = gensio_control(cmd, 0, GENSIO_CONTROL_SET, GENSIO_CONTROL_ARGS,
			(char *) tokens, NULL);
    if (rv) {
	add_output_buf(ii, "Done %llu Unable to set stdio args: %s", id,
		       gensio_err_to_str(rv));
	goto out_err;
    }

    rv = gensio_open_s(cmd);
    if (rv) {
	add_output_buf(ii, "Done %llu Unable to open stdio: %s", id,
		       gensio_err_to_str(rv));
	goto out_err;
    }

    rv = gensio_set_sync(cmd);
    if (rv) {
	add_output_buf(ii, "Done %llu Unable to set stdio sync: %s", id,
		       gensio_err_to_str(rv));
	goto out_err;
    }

    rv = 0;
    pos = 0;
    while (!rv) {
	if (pos < sizeof(buf) - 1) {
	    rv = gensio_read_s(cmd, &count, buf + pos, sizeof(buf) - pos,
			       &timeout);
	    if (!rv)
		pos += count;
	} else {
	    /* Throw away data after the buf size. */
	    rv = gensio_read_s(cmd, NULL, dummy, sizeof(dummy), &timeout);
	}
    }
    buf[pos] = '\0';

    rv = GE_INPROGRESS;
    while (rv == GE_INPROGRESS) {
	count = sizeof(ibuf);
	rv = gensio_control(cmd, 0, GENSIO_CONTROL_GET, GENSIO_CONTROL_WAIT_TASK,
			    ibuf, &count);
    }
    if (rv) {
	add_output_buf(ii, "Done %llu Unable to wait on stdio: %s", id,
		       gensio_err_to_str(rv));
	goto out_err;
    }
    rc = atoi(ibuf);

    rv = gensio_close_s(cmd);
    if (rv) {
	add_output_buf(ii, "Done %llu Unable to close stdio: %s", id,
		       gensio_err_to_str(rv));
	goto out_err;
    }

    add_output_msgrsp(ii, "Runrsp %llu %d %s", id, rc, buf);

    return;

 out_err:
    gensio_free(cmd);
}

static void
handle_write(struct ioinfo *ii, unsigned long long id, const char **tokens)
{
    int rv = 0, fd, len;

    if (!tokens[0]) {
	add_output_buf(ii, "Done %llu No file given", id);
	return;
    }

    if (!tokens[1]) {
	add_output_buf(ii, "Done %llu No data to write", id);
	return;
    }

    fd = open(tokens[0], O_WRONLY);
    if (fd == -1) {
	add_output_buf(ii, "Done %llu Unable to open file: %s", id,
		       strerror(errno));
	return;
    }

    len = strlen(tokens[1]);
    if (len > 0) {
	rv = write(fd, tokens[1], len);
	if (rv != len) {
	    if (rv == -1)
		add_output_buf(ii, "Done %llu Unable to write file: %s", id,
			       strerror(errno));
	    else
		add_output_buf(ii, "Done %llu Write file write %d, expected %d",
			       id, rv, len);
	} else {
	    rv = 0;
	}
    }

    close(fd);
    if (!rv)
	add_output_buf(ii, "Done %llu", id);
}

static void
handle_quit(struct ioinfo *ii, unsigned long long id, const char **tokens)
{
    struct accinfo *ai = ii->ai;
    struct gensio_link *l, *l2;

    ai->shutting_down = true;
    gensio_list_for_each_safe(&ai->ios, l, l2) {
	struct ioinfo *wii = gensio_container_of(l, struct ioinfo, link);

	add_output_buf(wii, "Shutdown %llu", id);

	if (wii == ii) /* Close on the final write. */
	    ii->close_on_write = true;
	else
	    start_ioinfo_close(wii);
    }
    check_shutdown(ai);
}

static struct {
    char *name;
    void (*handler)(struct ioinfo *ii, unsigned long long id,
		    const char **tokens);
} cmds[] = {
    { "Quit", handle_quit },
    { "Open", handle_open },
    { "Close", handle_close },
    { "Load", handle_load },
    { "Panic", handle_panic },
    { "Unload", handle_unload },
    { "Cycle", handle_cycle },
    { "Command", handle_command },
    { "Response", handle_response },
    { "Register", handle_register },
    { "Unregister", handle_unregister },
    { "EvEnable", handle_evenable },
    { "Runcmd", handle_runcmd },
    { "Write", handle_write },
    {}
};

static void
handle_buf(struct ioinfo *ii)
{
    int rv;
    int argc;
    const char **argv;
    unsigned long long id;
    char *end;
    unsigned int i;

    if (ii->closing)
	return;

    rv = gensio_str_to_argv(ii->ai->o, ii->inbuf, &argc, &argv, NULL);
    if (rv)
	return;

    if (argc < 2) {
	add_output_buf(ii, "Done - No id");
	goto out;
    }

    /* id is always second, it will be an unsigned long long. */
    id = strtoull(argv[1], &end, 0);
    if (argv[1][0] == '\0' || *end != '\0') {
	/* Not a valid number. */
	add_output_buf(ii, "Done - Invalid id");
	goto out;
    }

    for (i = 0; cmds[i].name; i++) {
	if (strcmp(cmds[i].name, argv[0]) == 0) {
	    cmds[i].handler(ii, id, argv + 2);
	    goto out;
	}
    }
    add_output_buf(ii, "Done %llu Unknown command: %s", id, argv[0]);
 out:
    gensio_argv_free(ii->ai->o, argv);
}

static int
io_event(struct gensio *io, void *user_data, int event, int err,
	 unsigned char *buf, gensiods *buflen,
	 const char *const *auxdata)
{
    struct ioinfo *ii = user_data;
    gensiods len, i;
    int rv;
    bool handle_it = false;

    switch (event) {
    case GENSIO_EVENT_READ:
	if (ii->closing)
	    return 0;

	if (err) {
	    if (err != GE_REMCLOSE)
		fprintf(stderr, "Error from io: %s\n", gensio_err_to_str(err));
	    start_ioinfo_close(ii);
	    return 0;
	}

	len = *buflen;
	for (i = 0; i < len; i++) {
	    if (buf[i] == '\0') {
		ii->inbuf[ii->inbuf_len] = '\0';
		handle_it = true;
		i++;
		break;
	    }
	    if (ii->inbuf_len >= sizeof(ii->inbuf) - 1)
		continue;
	    ii->inbuf[ii->inbuf_len++] = buf[i];
	}
	*buflen = i; /* We processed the characters up to the new line. */

	if (handle_it && ii->inbuf_len > 0) {
	    handle_buf(ii);
	    ii->inbuf_len = 0;
	}
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	if (ii->closing) {
	    gensio_set_write_callback_enable(ii->io, false);
	    return 0;
	}

	while (!gensio_list_empty(&ii->writelist)) {
	    struct gensio_link *l = gensio_list_first(&ii->writelist);
	    struct sendbuf *sb = gensio_container_of(l, struct sendbuf, link);

	    rv = gensio_write(ii->io, &i, sb->data + sb->pos, sb->len - sb->pos,
			      NULL);
	    if (rv) {
		if (rv != GE_REMCLOSE)
		    fprintf(stderr, "Error writing to io: %s\n",
			    gensio_err_to_str(rv));
		gensio_set_write_callback_enable(ii->io, false);
		start_ioinfo_close(ii);
		return 0;
	    }
	    sb->pos += i;
	    if (sb->pos >= sb->len) {
		gensio_list_rm(&ii->writelist, &sb->link);
		gensio_os_funcs_zfree(ii->ai->o, sb);
	    } else {
		break;
	    }
	}
	if (gensio_list_empty(&ii->writelist)) {
	    gensio_set_write_callback_enable(ii->io, false);
	    if (ii->close_on_write && !ii->closing)
		start_ioinfo_close(ii);
	}
	return 0;

    default:
	return GE_NOTSUP;
    }
}

/*
 * Handle a new connection.
 */
static int
io_acc_event(struct gensio_accepter *accepter, void *user_data,
	     int event, void *data)
{
    struct accinfo *ai = user_data;
    struct ioinfo *ii;

    if (event == GENSIO_ACC_EVENT_LOG) {
	struct gensio_loginfo *li = data;

	vfprintf(stderr, li->str, li->args);
	fprintf(stderr, "\n");
	return 0;
    }

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return GE_NOTSUP;

    if (ai->shutting_down) {
	gensio_free(data);
	return 0;
    }

    ii = calloc(1, sizeof(*ii));
    if (!ii) {
	fprintf(stderr, "Could not allocate info for new io\n");
	gensio_free(data);
	return 0;
    }
    ii->io = data;
    ii->ai = ai;
    gensio_list_init(&ii->writelist);
    gensio_list_add_tail(&ai->ios, &ii->link);
    gensio_set_callback(ii->io, io_event, ii);
    gensio_set_read_callback_enable(ii->io, true);
    add_output_buf(ii, "Ready");

    return 0;
}

int
main(int argc, char *argv[])
{
    struct ipmiinfo ipis[NUM_IPMI_INFO];
    struct accinfo ai;
    int rv;
    struct gensio_os_proc_data *proc_data = NULL;
    unsigned int i;

    if (argc < 2) {
	fprintf(stderr, "No gensio accepter given\n");
	return 1;
    }

    memset(&ai, 0, sizeof(ai));
    gensio_list_init(&ai.ios);
    memset(ipis, 0, sizeof(ipis));
    ai.ipis = ipis;

    rv = gensio_alloc_os_funcs(GENSIO_DEF_WAKE_SIG, &ai.o, 0);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    gensio_os_funcs_set_vlog(ai.o, do_vlog);

    rv = gensio_os_proc_setup(ai.o, &proc_data);
    if (rv) {
	fprintf(stderr, "Could not setup process data: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }

    for (i = 0; i < NUM_IPMI_INFO; i++) {
	ipis[i].fd = -1;
	ipis[i].ai = &ai;
	ipis[i].devidx = i;
	gensio_list_init(&ipis[i].cmd_rsps);
	ipis[i].close_waiter = gensio_os_funcs_alloc_waiter(ai.o);
	if (!ipis[i].close_waiter) {
	    fprintf(stderr, "Could not allocate close waiter, out of memory\n");
	    goto out_err;
	}
    }

    ai.waiter = gensio_os_funcs_alloc_waiter(ai.o);
    if (!ai.waiter) {
	rv = GE_NOMEM;
	fprintf(stderr, "Could not allocate waiter, out of memory\n");
	goto out_err;
    }

    rv = str_to_gensio_accepter(argv[1], ai.o, io_acc_event, &ai, &ai.acc);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", argv[1],
		gensio_err_to_str(rv));
	goto out_err;
    }

    rv = gensio_acc_startup(ai.acc);
    if (rv) {
	fprintf(stderr, "Could not start %s: %s\n", argv[1],
		gensio_err_to_str(rv));
	goto out_err;
    }

    rv = gensio_os_funcs_wait(ai.o, ai.waiter, 1, NULL);

 out_err:
    if (ai.acc)
	gensio_acc_free(ai.acc);
    if (ai.waiter)
	gensio_os_funcs_free_waiter(ai.o, ai.waiter);
    gensio_os_proc_cleanup(proc_data);
    gensio_os_funcs_free(ai.o);

    return !!rv;
}
