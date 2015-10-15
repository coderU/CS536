/*
 * transport.c
 *
 * CS536 PA2 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file.
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

#ifndef LOCAL_WINDOW_SIZE
#define LOCAL_WINDOW_SIZE 3072
#endif

#ifndef DEBUG
#define DEBUG true
#endif


enum { CSTATE_ESTABLISHED };    /* obviously you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    /* any other connection-wide global variables go here */
    tcp_seq th_local, th_remote, send_base;
    bool_t r_fin, l_fin, is_active;
} context_t;

uint16_t window;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */
    ctx->th_local = ctx->initial_sequence_num+1;
    ctx->send_base = ctx->initial_sequence_num+1;

    ctx->l_fin = false, ctx->r_fin = false;
    struct tcphdr *snd_header = (struct tcphdr *) calloc(1, sizeof(struct tcphdr));
    struct tcphdr *rcv_header = (struct tcphdr *) calloc(1, sizeof(struct tcphdr));
    if(is_active){
      //Send a SYN packet
      ctx->is_active = true;
      snd_header->th_flags = TH_SYN;
      //seq = x
      snd_header->th_seq = ctx->initial_sequence_num;
      snd_header->th_win = LOCAL_WINDOW_SIZE;
      window = LOCAL_WINDOW_SIZE;
      if (DEBUG) {
        fprintf(stderr, "sending: seq = %d\n", snd_header->th_seq);
      }
      stcp_network_send(sd, (void *)snd_header, sizeof(struct tcphdr), NULL);

      //Recieve the response for SYN
      stcp_network_recv(sd, (void *)rcv_header, sizeof(struct tcphdr));

      //Handle erro for fail handshake
      if (rcv_header->th_flags != (TH_SYN | TH_ACK)) {
        snd_header->th_flags = TH_FIN;
        stcp_network_send(sd, (void *)snd_header, sizeof(struct tcphdr), NULL);
        errno = ECONNREFUSED;
        perror("erro for fail handshake");
        return;
      }else if (snd_header->th_seq + 1 != rcv_header->th_ack){
        snd_header->th_flags = TH_FIN;
        stcp_network_send(sd, (void *)snd_header, sizeof(struct tcphdr), NULL);
        errno = ECONNREFUSED;
        perror("erro for fail handshake");
        return;
      }

      //Hand Shake successful, send back acknowledgement
      //ack = rcv_header seq +1
      //seq = rcv_header ack
      snd_header->th_flags = TH_ACK;
      snd_header->th_seq = rcv_header->th_ack;
      snd_header->th_ack = rcv_header->th_seq + 1;
      if (DEBUG) {
        fprintf(stderr, "sending: seq = %d ack = %d\n", snd_header->th_seq, snd_header->th_ack);
      }
      stcp_network_send(sd, (void *)snd_header, sizeof(struct tcphdr), NULL);
      ctx->th_remote = rcv_header->th_seq+1;
    } else{
      ctx->is_active = false;
      //Wait for one to arrive
      stcp_network_recv(sd, (void *)rcv_header, sizeof(struct tcphdr));
      ctx->th_remote = rcv_header->th_seq+1;
      window = rcv_header->th_win;
      // snd_header = rcv_header;
      if (rcv_header->th_flags != TH_SYN || rcv_header->th_seq > 255) {
        snd_header->th_flags = TH_FIN;
        stcp_network_send(sd, (void *)snd_header, sizeof(struct tcphdr), NULL);
        return;
      }

      snd_header->th_flags = TH_SYN|TH_ACK;
      // seq = y
      snd_header->th_seq = ctx->initial_sequence_num;
      // ack = rcv_header seq + 1
      snd_header->th_ack = rcv_header->th_seq + 1;
      if (DEBUG) {
        fprintf(stderr, "sending: seq = %d ack = %d\n", snd_header->th_seq, snd_header->th_ack);
      }
      stcp_network_send(sd, (void *)snd_header, sizeof(struct tcphdr), NULL);
      stcp_network_recv(sd, (void *)rcv_header, sizeof(struct tcphdr));
      if (rcv_header->th_flags != TH_ACK) {
          errno = ECONNREFUSED; perror("erro for fail handshake");
          return;
      }

    }
    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);


    ctx->th_local++;
    ctx->th_remote++;
    ctx->send_base = ctx->th_local;

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
    free(snd_header);
    free(rcv_header);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);
    int t = 0;
    #ifdef FIXED_INITNUM
        /* please don't change this! */
        ctx->initial_sequence_num = 1;
    #else
        srand(*(unsigned int *)&t);
        int r = rand();
        ctx->initial_sequence_num = r%256;
    #endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);
    struct tcphdr *tcp_header = (struct tcphdr *) calloc(1, sizeof(struct tcphdr));
    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, 0, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
          if (ctx->th_local < ctx->send_base + window) {


          }
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
        }

        /* etc. */
    }
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 *
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}
