/* network.c--implements unreliability during packet transmission */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include "mysock_impl.h"
#include "network.h"
#include "network_io.h"
#include "transport.h"  /* for dprintf() */




/* helper function for stcp_network_send(); this takes care of unreliable
 * delivery simulation, etc, before passing a packet off to
 * _network_send_packet() for actual transmission over the network.
 */
int _network_send(mysocket_t sd, const void *buf, size_t len)
{
    mysock_context_t *sock_ctx = _mysock_get_context(sd);
    network_context_t *ctx;

    assert(sock_ctx && buf);
    ctx = &sock_ctx->network_state;


    if (!ctx->is_reliable)
    {
        switch (rand_r(&ctx->random_seed) & 0x1f)
        {
        case 1:
            /* send duplicate */
            dprintf("====>network_send:duplicating the packet\n");
            _network_send_packet(ctx, buf, len);
            break;

        case 2:
            /* store the packet in our queue. Will send it later */
            dprintf("====>network_send:keeping the packet in our queue\n");
            assert(len <= sizeof(ctx->copy_buffer));
            memcpy(&ctx->copy_buffer, buf, len);
            ctx->copy_buf_len = len;
            ctx->copied = TRUE;
            _network_send_packet(ctx, buf, len);
            return len;

        case 3:
            /* forget about this packet, we will send the packet which
             * we stored sometime back.
             */
            if (ctx->copied)
            {
                dprintf("====>network_send:sending the packet stored "
                        "in our queue\n");
                _network_send_packet(ctx, ctx->copy_buffer, ctx->copy_buf_len);
                _network_send_packet(ctx, buf, len);
            }
            else
            {
                dprintf("====>network_send:duplicating the packet\n");
                _network_send_packet(ctx, buf, len);
            }
            return len;
        case 4:
        case 5:
            char packet[MAX_IP_PAYLOAD_LEN];
            memcpy(packet, buf, len);
            if(len<sizeof(tcphdr))
                return len;
            struct tcphdr *header;
            header = (struct tcphdr *) packet;
            unsigned int tar;
            unsigned int temp;
            switch(rand_r(&ctx->random_seed)%4)
            {
                case 0://Do corrupt for header only (large)
                    dprintf(stderr, "====>network_send:corrupting the packet - header -l\n");
                    header->th_seq = ntohl(htonl(header->th_seq) + rand());
                    memcpy(packet+8, &header->th_seq, 4);
                    break;
                case 1://Do corrupt for header only (small)
                    dprintf(stderr, "====>network_send:corrupting the packet - header -s\n");
                    header->th_seq = ntohl(htonl(header->th_seq) + rand()%3172);
                    memcpy(packet+8, &header->th_seq, 4);
                    break;
                case 2://Do corrupt for payload only
                    dprintf(stderr, "====>network_send:corrupting the packet - payload\n");
                    tar=20;
                    while(tar<len-4)
                    {
                        temp = rand_r(&ctx->random_seed);
                        memcpy(packet+tar, &temp, sizeof(int));
                        tar = tar + rand_r(&ctx->random_seed)%16 + 4;
                    }
                    break;
                case 3://Do corrupt for both header and payload
                    dprintf(stderr, "====>network_send:corrupting the packet - both\n");

                    tar=8;
                    while(tar<len-4)
                    {
                        temp = rand_r(&ctx->random_seed);
                        memcpy(packet+tar, &temp, sizeof(int));
                        tar = tar + rand_r(&ctx->random_seed)%16 + 4;
                    }
                    break;
                    
                default:
                    dprintf(stderr, "====>network_send:corrupting the packet - Error\n");
            }
            _network_send_packet(ctx, packet, len);
            return len;
        default:
            /* send what we were supposed to send */
            break;
        }
    }

    return _network_send_packet(ctx, buf, len);
}

/* helper function for stcp_network_recv() */
int _network_recv(mysocket_t sd, void *dst, size_t max_len)
{
    int len;
    mysock_context_t *ctx = _mysock_get_context(sd);

    assert(ctx && dst);
    len = _mysock_dequeue_buffer(ctx, &ctx->network_recv_queue,
                                 dst, max_len, FALSE);

    return len;
}

