#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pppd/pppd.h>

#include <arpa/inet.h>
#include <pppd/fsm.h>
#include <pppd/ipcp.h>

#include "pppd-plugin-message.h"

char pppd_version[] = VERSION;

static int f5_vpn_pipe_fd = -1;

static void
my_ip_up (void *opaque, int arg)
{
	(void) opaque;
	(void) arg;

	ipcp_options opts = ipcp_gotoptions[0];
	PppdPluginNotification msg;
	msg.local_addr.s_addr = opts.ouraddr;
	msg.remote_addr.s_addr = opts.hisaddr;
	strncpy (msg.ifname, ifname, sizeof (msg.ifname));
	if(write (f5_vpn_pipe_fd, &msg, sizeof (msg)) == -1)
		fprintf(stderr, "write error: %s\n", strerror(errno));
}

void
plugin_init (void)
{
	f5_vpn_pipe_fd = atoi (getenv ("F5_VPN_PPPD_PLUGIN_FD"));
	add_notifier (&ip_up_notifier, my_ip_up, NULL);
}
