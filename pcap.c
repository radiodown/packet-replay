#include "syshead.h"
#include "basic.h"
#include "pcap.h"
#include "options.h"
#include "logger.h"
#include "send.h"
#include "crc32.h"

#define MAX_SESSION 256

/* global */
PCAP_HDR phdr;
TCP_SESSION *tcp_session_list[MAX_SESSION];


/* send all sessions payload */
int send_pcap(options *o)
{
	for (int i = 0; i < MAX_SESSION; i++)
	{
		if (tcp_session_list[i] == NULL)
			break;
		if (send_session(o, tcp_session_list[i]))
			return 1;
	}
	return 0;
}

/* send tcp session payload  */
int send_session(options *o, TCP_SESSION *session)
{
	int port = 0;
	int ret = 0;

	if (o->port == 0)
		port = ntohs(session->head->tcp->dest);
	else
		port = o->port;

	TCP_SESSION *ptr = session->head;

	int assemble_cnt = 0;
	int assemble_size = 0;

	while (ptr != NULL)
	{
		if (ptr->segmented)
		{
			/* if data segmented, assemble later  */
			assemble_cnt++;
			assemble_size += ptr->payload_size;
			ptr = ptr->prev;
			continue;
		}

		if (ptr->payload_size > 0)
		{	
			/* before packet was segmented, not me */
			if (!ptr->segmented && assemble_cnt > 0)
			{
				unsigned char *assembled = calloc(assemble_size, sizeof(unsigned char));

				/* goto first segmented packet */
				TCP_SESSION *first = ptr;
				for (int i = 0; i < assemble_cnt; i++)
				{
					first = first->next;
				}

				/* Assemble Data */
				for (int i = 0; i < assemble_cnt; i++)
				{
					strncat(assembled, first->payload, first->payload_size);
					first = first->prev;
				}

				/* Send assembled data */
				ret = send_tcp(port, o->address, assembled, assemble_size);
				free(assembled);

				if (ret)
					return ret;

				assemble_cnt = 0;
				assemble_size = 0;
			}

			/* Send Ack payload */
			ret = send_tcp(port, o->address, ptr->payload, ptr->payload_size);
			if (ret)
				return ret;
		}
		ptr = ptr->prev;
	}

	return 0;
}

void print_pcap()
{
	TCP_SESSION *session;
	char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];

	for (int i = 0; i < MAX_SESSION; i++)
	{
		if (tcp_session_list[i] == NULL)
			break;

		session = tcp_session_list[i]->head;

		for (int j = 1; session != NULL; j++)
		{
			memset(saddr,0,INET_ADDRSTRLEN);
			memset(daddr,0,INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(session->ip->saddr), saddr, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(session->ip->daddr), daddr, INET_ADDRSTRLEN);

			logger(LOG_INFO, "\n[   #%d - %d Packet Frame   ]", session->session_id, j);
			logger(LOG_INFO, "%d.%d %d bytes %d captured", session->pcap->ts_sec, session->pcap->ts_subsec, session->pcap->incl_len, session->pcap->orig_len);
			logger(LOG_INFO, "MAC %s -> %s", ether_ntoa(session->eth->h_source), ether_ntoa(session->eth->h_dest));
			logger(LOG_INFO, "TCP %s:%d -> %s:%d", saddr, ntohs(session->tcp->source), daddr, ntohs(session->tcp->dest));

			if ( !session->tcp->syn && session->tcp->ack && !session->tcp->fin)
			{
				if (session->segmented)
					logger(LOG_INFO, "Segmented Payload");

				logger(LOG_INFO, "Payload : %d bytes", session->payload_size);
				dump_hex(session->payload, session->payload_size);
			}
			session = session->prev;
		}
	}
}



void match_tcp_session_to_list(TCP_SESSION *session)
{
	int i = 0;

	/* Syn Packet (new session) */
	if (session->tcp->syn && !session->tcp->ack  )
	{
		for (i = 0; i < MAX_SESSION; i++)
		{
			if (tcp_session_list[i] == NULL)
			{
				tcp_session_list[i] = session;
				session->head = tcp_session_list[i];
				session->session_id = i;
				session->packet_id = 1;
				break;
			}
		}
		return;
	}

	/* Add Packet List to Exist Session */
	for (i = 0; i < MAX_SESSION; i++)
	{
		if (tcp_session_list[i] == NULL)
			break;

		/* search 5-tuple */
		if (tcp_session_list[i]->ip->saddr == session->ip->saddr && tcp_session_list[i]->ip->daddr == session->ip->daddr)
		{
			if (tcp_session_list[i]->tcp->source == session->tcp->source && tcp_session_list[i]->tcp->dest == session->tcp->dest)
			{

				/* Find Segmented Packet */
				if (tcp_session_list[i]->payload_size > 0)
				{
					if (htonl(tcp_session_list[i]->tcp->th_seq) + tcp_session_list[i]->payload_size == htonl(session->tcp->th_seq))
					{
						if (tcp_session_list[i]->tcp->th_ack == session->tcp->th_ack)
						{
							if ( !tcp_session_list[i]->tcp->syn && tcp_session_list[i]->tcp->ack && !tcp_session_list[i]->tcp->fin &&
								!session->tcp->syn && session->tcp->ack && !session->tcp->fin)
							{
								tcp_session_list[i]->segmented = 1;
								session->segmented = 1;
							}
						}
					}
				}

				session->packet_id = tcp_session_list[i]->packet_id + 1;
				session->session_id = i;

				/* add to session list */
				session->head = tcp_session_list[i]->head;
				tcp_session_list[i]->prev = session;
				session->next = tcp_session_list[i];
				tcp_session_list[i] = session;
				
				return;
			}
		}

		/* search 5-tuple */
		if (tcp_session_list[i]->ip->daddr == session->ip->saddr && tcp_session_list[i]->ip->saddr == session->ip->daddr)
		{
			if (tcp_session_list[i]->tcp->dest == session->tcp->source && tcp_session_list[i]->tcp->source == session->tcp->dest)
			{
				session->packet_id = tcp_session_list[i]->packet_id + 1;
				session->session_id = i;

				/* add to session list */
				session->head = tcp_session_list[i]->head;
				tcp_session_list[i]->prev = session;
				session->next = tcp_session_list[i];
				tcp_session_list[i] = session;
				return;
			}
		}
	}
	

	/* there is no Exist Session, add New Session */
	tcp_session_list[i] = session;
	session->head = tcp_session_list[i];
	session->session_id = i;
	session->packet_id = 1;

	return;
}

void set_session(TCP_SESSION *session)
{
	session->eth = (ETH *)(session->raw);
	session->ip = (IP *)(session->raw + sizeof(ETH));
	session->tcp = (TCP *)(session->raw + sizeof(IP) + sizeof(ETH));
	// session->tcp_op = (TCP_OP *)(session->raw + sizeof(IP) + sizeof(ETH) + sizeof(TCP));
	session->payload = session->raw + sizeof(ETH) + sizeof(IP) + session->tcp->doff * 4;
	session->payload_size = session->pcap->incl_len - sizeof(ETH) - sizeof(IP) - session->tcp->doff * 4;

	if (has_crc32(session))
	{
		session->payload_size -= 4;
	}
}

void init_session(TCP_SESSION *session)
{
	session->pcap = calloc(1, sizeof(PCAPREC_HDR));
}

void free_session(TCP_SESSION *session)
{
	safe_free(session->pcap);
	safe_free(session->raw);
	safe_free(session);
}

int parse_session(FILE *fp)
{
	for (;;)
	{
		TCP_SESSION *session = calloc(1, sizeof(TCP_SESSION));

		init_session(session);

		if (fread(session->pcap, 1, sizeof(PCAPREC_HDR), fp) == 0)
			break;

		session->raw = calloc(session->pcap->incl_len + 1, sizeof(unsigned char));

		int cnt = fread(session->raw, sizeof(unsigned char), session->pcap->incl_len, fp);

		if (cnt != session->pcap->incl_len)
		{
			logger(LOG_ERROR, "File read error while Parsing Pcap");
			return 1;
		}

		set_session(session);

		if (session->ip->protocol == IPPROTO_TCP)
		{
			match_tcp_session_to_list(session);
		}
		else
		{
			free_session(session);
		}
	}
	return 0;
}

int pcap_open(FILE *fp, char *file)
{
	fp = fopen(file, "r");

	return fp == NULL;
}

void pcap_close(FILE *fp)
{
	if (fp != NULL)
		fclose(fp);
}

void pcap_info(FILE *fp)
{
	fread(&phdr, sizeof(PCAP_HDR), 1, fp);
	logger(LOG_INFO, "     [   PCAP INFO   ]");
	logger(LOG_INFO, "   magic number: %x", phdr.magic_number);
	logger(LOG_INFO, "        version: %d.%d", phdr.version_major, phdr.version_minor);
	logger(LOG_INFO, "       timezone: %d", phdr.thiszone);
	logger(LOG_INFO, "      timestamp: %d", phdr.sigfigs);
	logger(LOG_INFO, "captured length: %d", phdr.snaplen);
	logger(LOG_INFO, "      link type: %d", phdr.network);
	logger(LOG_INFO, "");
}

int parse_pcap(options *o)
{
	FILE *fp = NULL;
	int ret = 0;

	fp = fopen(o->file, "r");
	if (fp == NULL)
	{
		logger(LOG_ERROR, "Cannot open file : %s", o->file);
		return 1;
	}

	pcap_info(fp);

	ret = parse_session(fp);

	fclose(fp);

	return ret;
}