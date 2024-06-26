#include "syshead.h"
#include "options.h"
#include "pcap.h"
#include "server.h"

int main(int argc, char *argv[])
{
	options o;
	if (parse_argv(&o, argc, argv))
		return 1;

	if(o.mode == MODE_SERVER){
		server(o.port);
	}

	if (parse_pcap(&o))
		return 1;

	if (o.show)
		print_pcap();
	

	if (o.address != NULL)
		send_pcap(&o);
	
	return 0;
}
