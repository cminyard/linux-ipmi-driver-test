
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gensio/gensio.h>
#include <gensio/gensio_openipmi_oshandler.h>
#include <gensio/gensio_list.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/internal/ipmi_event.h>

struct tinfo;

struct sendbuf {
    struct gensio_link link;
    struct tinfo *ti;
    gensiods len;
    gensiods pos;
    unsigned char *data;
    unsigned long long id;
    bool sent;
    bool done;

    char response[512];
};

struct tinfo {
    int rv;

    unsigned long long curr_id;

    struct gensio_os_funcs *o;
    struct gensio *helper;

    os_handler_t *oo;
    ipmi_con_t *icon;

    struct gensio_waiter *waiter;

    bool ready;
    bool closing;
    unsigned int close_wait_count;

    char inbuf[1024];
    gensiods inbuf_len;

    /* List of struct sendbuf to write. */
    struct gensio_list writelist;

    /* List of struct sendbuf waiting for a response. */
    struct gensio_list waitlist;
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

static struct sendbuf *
alloc_sendbuf(struct tinfo *ti, const char *cmd, const char *str, va_list ap)
{
    struct gensio_os_funcs *o = ti->o;
    struct sendbuf *s;
    va_list ap2;
    size_t len, len2;
    char dummy[21];

    va_copy(ap2, ap);
    len = vsnprintf(dummy, 21, str, ap);
    len += snprintf(dummy, 21, "%s %llu ", cmd, ti->curr_id);
    s = gensio_os_funcs_zalloc(o, sizeof(struct sendbuf) + len + 2);
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
sendbuf_free(struct sendbuf *sb)
{
    gensio_os_funcs_zfree(sb->ti->o, sb);
}

static void
sendbuf_unlink_free(struct tinfo *ti, struct sendbuf *sb)
{
    if (sb->sent)
	gensio_list_rm(&ti->waitlist, &sb->link);
    else
	gensio_list_rm(&ti->writelist, &sb->link);
    sendbuf_free(sb);
}

static struct sendbuf *
helper_vsend(struct tinfo *ti, const char *cmd, const char *str, va_list ap)
{
    struct sendbuf *s;

    s = alloc_sendbuf(ti, cmd, str, ap);
    gensio_list_add_tail(&ti->writelist, &s->link);
    gensio_set_write_callback_enable(ti->helper, true);

    return s;
}

__attribute__ ((__format__ (__printf__, 3, 4)))
static struct sendbuf *
helper_send(struct tinfo *ti, const char *cmd, const char *str, ...)
{
    va_list ap;
    struct sendbuf *s;

    va_start(ap, str);
    s = helper_vsend(ti, cmd, str, ap);
    va_end(ap);

    return s;
}

static int
helper_wait_done(struct sendbuf *sb)
{
    gensio_time timeout = { 10, 0 };
    int rv;

    while (!sb->done && !sb->ti->rv) {
	rv = gensio_os_funcs_service(sb->ti->o, &timeout);
	if (rv && rv != GE_INTERRUPTED)
	    return rv;
    }
    if (sb->response[0])
	return -1;
    return 0;
}

int
helper_cmd_resp(struct tinfo *ti, const char *cmd, const char *str, ...)
{
    va_list ap;
    struct sendbuf *sb;
    int rv;

    va_start(ap, str);
    sb = helper_vsend(ti, cmd, str, ap);
    va_end(ap);

    if (!sb) {
	fprintf(stderr, "Unable to send command '%s %s'", cmd, str);
	return 1;
    }
    rv = helper_wait_done(sb);
    if (rv > 0) {
	fprintf(stderr, "Command %s %s: Error waiting on sendbuf: %s\n",
		cmd, str, gensio_err_to_str(rv));
	rv = 1;
    } else if (rv < 0) {
	fprintf(stderr, "Command %s %s: Load error response: %s\n",
		cmd, str, sb->response);
	rv = 1;
    }
    sendbuf_unlink_free(sb->ti, sb);
    return rv;
}

static int
test_load_unload(struct tinfo *ti)
{
    int rv;

    rv = helper_cmd_resp(ti, "Load", "ipmi_msghandler");
    if (rv)
	return rv;
    rv = helper_cmd_resp(ti, "Unload", "ipmi_msghandler");
    if (rv)
	return rv;
    rv = helper_cmd_resp(ti, "Load", "i2c-i801 ipmi_msghandler ipmi_si ipmi_devintf ipmi_ssif");
    rv = helper_cmd_resp(ti, "Unload", "ipmi_ssif ipmi_devintf ipmi_si ipmi_msghandler i2c-i801");
    if (rv)
	return rv;
    return 0;
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

static struct sendbuf *
find_waiting_sendbuf(struct tinfo *ti, char **idptr)
{
    unsigned long long id;
    char *idstr = *idptr;
    struct gensio_link *l;

    id = strtoull(idstr, idptr, 0);
    gensio_list_for_each(&ti->waitlist, l) {
	struct sendbuf *sb = gensio_container_of(l, struct sendbuf, link);

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
    struct sendbuf *sb;

    if (strcmp(ti->inbuf, "Ready") == 0) {
	/* Just ignore this. */
    } else if (strncmp(ti->inbuf, "Done ", 5) == 0) {
	end = ti->inbuf + 5;
	sb = find_waiting_sendbuf(ti, &end);
	if (!sb) {
	    fprintf(stderr, "Unknown response: %s\n", ti->inbuf);
	} else {
	    if (*end == ' ')
		end++;
	    copy_string(sb->response, end, sizeof(sb->response));
	    sb->done = true;
	}
    } else {
	fprintf(stderr, "Unknown response type: %s\n", ti->inbuf);
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
    bool handle_it = false;

    switch (event) {
    case GENSIO_EVENT_READ:
	if (ti->closing)
	    return 0;

	if (err) {
	    fprintf(stderr, "Error from helper: %s\n", gensio_err_to_str(err));
	    ti->rv = 1;
	    start_test_close(ti);
	    return 0;
	}

	len = *buflen;
	for (i = 0; i < len; i++) {
	    if (buf[i] == '\n' || buf[i] == '\r') {
		ti->inbuf[ti->inbuf_len] = '\0';
		/*
		 * Note that you could continue to process characters
		 * but this demonstrates that you can process partial
		 * buffers, which can sometimes simplify code.
		 */
		handle_it = true;
		i++;
		break;
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
	    struct sendbuf *sb = gensio_container_of(l, struct sendbuf, link);

	    rv = gensio_write(ti->helper, &i,
			      sb->data + sb->pos, sb->len - sb->pos,
			      NULL);
	    if (rv) {
		if (rv != GE_REMCLOSE)
		    fprintf(stderr, "Error writing to io: %s\n",
			    gensio_err_to_str(rv));
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
	fprintf(stderr, "IPMI connection failure: %x\n", err);
	ti->icon = NULL;
	con->close_connection(con);
	if (ti->ready)
	    start_test_close(ti);
    }

    gensio_os_funcs_wake(ti->o, ti->waiter);
}

static void
helper_open_done(struct gensio *io, int err, void *open_data)
{
    struct tinfo *ti = open_data;

    if (ti->closing)
	return;

    if (err) {
	fprintf(stderr, "helper connection failure: %s\n",
		gensio_err_to_str(err));
	gensio_free(io);
	ti->helper = NULL;
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
    int rv;
    gensio_time timeout;

    memset(&ti, 0, sizeof(ti));

    gensio_list_init(&ti.writelist);
    gensio_list_init(&ti.waitlist);

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

    if (ipmi_setup_con(&ti)) {
	ti.rv = 1;
	goto out_close;
    }

    if (helper_setup_con(&ti)) {
	ti.rv = 1;
	start_test_close(&ti);
	goto out_wait_close;
    }

    timeout.secs = 2;
    timeout.nsecs = 0;
    rv = gensio_os_funcs_wait(ti.o, ti.waiter, 2, &timeout);
    if (rv) {
	fprintf(stderr, "Error setting up connections: %s\n",
		gensio_err_to_str(rv));
	ti.rv = 1;
	goto out_close;
    }

    ti.ready = true;

    test_load_unload(&ti);
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
    if (proc_data)
	gensio_os_proc_cleanup(proc_data);
    gensio_os_funcs_free(ti.o);

    return ti.rv;
}
