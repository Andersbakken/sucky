# define RTLD_NEXT	((void *) -1l)

#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef int (*Accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
typedef int (*Accept4)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
typedef int (*Close)(int fd);
typedef int (*Creat)(const char *pathname, mode_t mode);
typedef int (*Epoll_create)(int size);
typedef int (*Epoll_create1)(int flags);
typedef int (*Open)(const char *pathname, int flags, ...);
typedef int (*Openat)(int dirfd, const char *pathname, int flags, ...);
typedef int (*Openat2)(int dirfd, const char *pathname, const void *how, size_t size); // it's really a struct
typedef int (*Pipe)(int pipefd[2]);
typedef int (*Socket)(int domain, int type, int protocol);
typedef int (*Socketpair)(int domain, int type, int protocol, int sv[2]);

struct FileDescriptor
{
    int fd;
    pthread_t thread;
};

struct Originals {
    Accept accept;
    Accept4 accept4;
    Close close;
    Creat creat;
    Epoll_create epoll_create;
    Epoll_create1 epoll_create1;
    Open open;
    Openat openat;
    Openat2 openat2;
    Pipe pipe;
    Socket socket;
    Socketpair socketpair;

    struct FileDescriptor *fds;
    size_t count;
};

static struct Originals *sOriginals = 0;
static pthread_once_t sOnce = PTHREAD_ONCE_INIT;
static pthread_mutex_t sMutex = PTHREAD_MUTEX_INITIALIZER;
static int sVerbose = 0;

void createOriginals()
{
    sVerbose = getenv("SUCKY_VERBOSE") != 0;
    assert(!sOriginals);
    sOriginals = (struct Originals *)malloc(sizeof(struct Originals));
    sOriginals->fds = 0;
    sOriginals->count = 0;
    sOriginals->accept = (Accept)dlsym(RTLD_NEXT, "accept");
    sOriginals->accept4 = (Accept4)dlsym(RTLD_NEXT, "accept4");
    sOriginals->close = (Close)dlsym(RTLD_NEXT, "close");
    sOriginals->creat = (Creat)dlsym(RTLD_NEXT, "creat");
    sOriginals->epoll_create = (Epoll_create)dlsym(RTLD_NEXT, "epoll_epoll");
    sOriginals->epoll_create1 = (Epoll_create1)dlsym(RTLD_NEXT, "epoll_epoll");
    sOriginals->open = (Open)dlsym(RTLD_NEXT, "open");
    sOriginals->openat = (Openat)dlsym(RTLD_NEXT, "openat");
    sOriginals->openat2 = (Openat2)dlsym(RTLD_NEXT, "openat2");
    sOriginals->pipe = (Pipe)dlsym(RTLD_NEXT, "pipe");
    sOriginals->socket = (Socket)dlsym(RTLD_NEXT, "socket");
    sOriginals->socketpair = (Socketpair)dlsym(RTLD_NEXT, "socketpair");
}

struct Originals *originals()
{
    pthread_once(&sOnce, createOriginals);
    assert(sOriginals);
    return sOriginals;
}

void addFileDescriptors(int fd1, int fd2)
{
    pthread_t thread = pthread_self();
    pthread_mutex_lock(&sMutex);
    if (fd2 == -1) {
        sOriginals->fds = realloc(sOriginals->fds, sizeof(struct FileDescriptor) * sOriginals->count + 1);
        struct FileDescriptor *desc = &sOriginals->fds[sOriginals->count++];
        desc->fd = fd1;
        desc->thread = thread;
    } else {
        sOriginals->fds = realloc(sOriginals->fds, sizeof(struct FileDescriptor) * sOriginals->count + 2);
        struct FileDescriptor *desc = &sOriginals->fds[sOriginals->count++];
        desc->fd = fd1;
        desc->thread = thread;
        desc = &sOriginals->fds[sOriginals->count++];
        desc->fd = fd2;
        desc->thread = thread;
    }
    pthread_mutex_unlock(&sMutex);
}

int socket(int domain, int type, int protocol)
{
    int ret = originals()->socket(domain, type, protocol);
    if (ret != -1) {
        addFileDescriptors(ret, -1);
    }
    if (sVerbose) {
        fprintf(stderr, "SUCKY: socket(%d, %d, %d) -> %d\n", domain, type, protocol, ret);
    }
    return ret;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int ret = originals()->accept(sockfd, addr, addrlen);
    if (ret != -1) {
        addFileDescriptors(ret, -1);
    }
    if (sVerbose) {
        fprintf(stderr, "SUCKY: accept(%d, %p, %p) -> %d\n", sockfd, addr, addrlen, ret);
    }
    return ret;
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    int ret = originals()->accept4(sockfd, addr, addrlen, flags);
    if (ret != -1) {
        addFileDescriptors(ret, -1);
    }
    if (sVerbose) {
        fprintf(stderr, "SUCKY: accept4(%d, %p, %p, 0x%x) -> %d\n", sockfd, addr, addrlen, flags, ret);
    }
    return ret;
}

int socketpair(int domain, int type, int protocol, int sv[2])
{
    int ret = originals()->socketpair(domain, type, protocol, sv);
    if (ret != -1) {
        addFileDescriptors(sv[0], sv[1]);
    }
    if (sVerbose) {
        fprintf(stderr, "SUCKY: socketpair(%d, %d, %d, [%d, %d]) -> %d\n", domain, type, protocol, sv[0], sv[1], ret);
    }
    return ret;
}

int pipe(int pipefd[2])
{
    int ret = originals()->pipe(pipefd);
    if (ret != -1) {
        addFileDescriptors(pipefd[0], pipefd[1]);
    }
    if (sVerbose) {
        fprintf(stderr, "SUCKY: pipe([%d, %d]) -> %d\n", pipefd[0], pipefd[1], ret);
    }
    return ret;
}

int close(int fd)
{
    pthread_t thread = pthread_self();
    pthread_mutex_lock(&sMutex);
    int ret = originals()->close(fd);
    if (sVerbose) {
        fprintf(stderr, "SUCKY: close(%d) -> %d\n", fd, ret);
    }
    if (ret != -1) {
        size_t i;
        for (i=0; i<sOriginals->count; ++i) {
            if (sOriginals->fds[i].fd == fd) {
                if (!pthread_equal(sOriginals->fds[i].thread, thread)) {
                    fprintf(stderr, "SUCKY: file descriptor %d closed from different thread than it was created in\n", fd);
                    abort();
                }
                if (i + 1 < sOriginals->count) {
                    memmove(sOriginals + i, sOriginals + i + 1, sizeof(struct FileDescriptor) * sOriginals->count - i - 1);
                }
                if (!--sOriginals->count) {
                    free(sOriginals->fds);
                    sOriginals->fds = 0;
                } else {
                    sOriginals->fds = realloc(sOriginals->fds, sizeof(struct FileDescriptor) * sOriginals->count);
                }
            }
        }
    }

    pthread_mutex_unlock(&sMutex);
    return ret;
}

int open(const char *pathname, int flags, ...)
{
    int ret;
    if (flags & O_CREAT) {
        va_list list;
        va_start(list, flags);
        mode_t mode = va_arg(list, mode_t);
        va_end(list);
        ret = originals()->open(pathname, flags, mode);
        if (sVerbose) {
            fprintf(stderr, "SUCKY: open(%s, 0x%x, 0x%x) -> %d\n", pathname, flags, mode, ret);
        }
    } else {
        ret = originals()->open(pathname, flags);
        if (sVerbose) {
            fprintf(stderr, "SUCKY: open(%s, 0x%x) -> %d\n", pathname, flags, ret);
        }
    }
    if (ret != -1) {
        addFileDescriptors(ret, -1);
    }
    return ret;
}

int creat(const char *pathname, mode_t mode)
{
    int ret = originals()->creat(pathname, mode);
    if (ret != -1) {
        addFileDescriptors(ret, -1);
    }
    if (sVerbose) {
        fprintf(stderr, "SUCKY: creat(%s, 0x%x) -> %d\n", pathname, mode, ret);
    }
    return ret;
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
    int ret;
    if (flags & O_CREAT) {
        va_list list;
        va_start(list, flags);
        mode_t mode = va_arg(list, mode_t);
        va_end(list);
        ret = originals()->openat(dirfd, pathname, flags, mode);
        if (sVerbose) {
            fprintf(stderr, "SUCKY: openat(%d, %s, 0x%x, 0x%x) -> %d\n", dirfd, pathname, flags, mode, ret);
        }
    } else {
        ret = originals()->openat(dirfd, pathname, flags);
        if (sVerbose) {
            fprintf(stderr, "SUCKY: openat(%d, %s, 0x%x) -> %d\n", dirfd, pathname, flags, ret);
        }
    }
    if (ret != -1) {
        addFileDescriptors(ret, -1);
    }
    return ret;
}

int openat2(int dirfd, const char *pathname, const void *how, size_t size)
{
    int ret = originals()->openat2(dirfd, pathname, how, size);
    if (ret != -1) {
        addFileDescriptors(ret, -1);
    }
    if (sVerbose) {
        fprintf(stderr, "SUCKY: openat2(%d, %s, %p, %zu) -> %d\n", dirfd, pathname, how, size, ret);
    }
    return ret;
}

int epoll_create(int size)
{
    int ret = originals()->epoll_create(size);
    if (ret != -1) {
        addFileDescriptors(ret, -1);
    }
    if (sVerbose) {
        fprintf(stderr, "SUCKY: epoll_create(%d) -> %d\n", size, ret);
    }
    return ret;
}

int epoll_create1(int flags)
{
    int ret = originals()->epoll_create1(flags);
    if (ret != -1) {
        addFileDescriptors(ret, -1);
    }
    if (sVerbose) {
        fprintf(stderr, "SUCKY: epoll_create1(0x%x) -> %d\n", flags, ret);
    }
    return ret;
}
