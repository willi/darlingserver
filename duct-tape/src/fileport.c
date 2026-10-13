#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape.h>

#include <kern/ipc_misc.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_port.h>
#include <sys/errno.h>

// Fileports (`fileport_makeport()`, `fileport_makefd()`): Mach send rights that stand for an open file, following
// sys_fileport_makeport() and sys_fileport_makefd() in XNU's bsd/kern/kern_descrip.c. A fileport's fileglob is the
// descriptor darlingserver keeps open for the file; it's closed when the port has no senders left.

int close(int fd);
int dup(int fd);

struct fileglob {
	int fd;
};

void fileport_releasefg(struct fileglob* fg) {
	close(fg->fd);
	free(fg);
};

int dtape_fileport_makeport(dtape_task_t* task, int fd, uint32_t* out_name) {
	struct fileglob* fg;
	ipc_port_t fileport;
	mach_port_name_t name;

	fg = malloc(sizeof(*fg));
	if (!fg) {
		close(fd);
		return -ENOMEM;
	}
	fg->fd = fd;

	// the port comes with a send right, and the fileglob is released when it has no senders
	fileport = fileport_alloc(fg);
	if (fileport == IPC_PORT_NULL) {
		fileport_releasefg(fg);
		return -EAGAIN;
	}

	// deallocates the port (and so releases the fileglob) on failure
	name = ipc_port_copyout_send(fileport, task->xnu_task.itk_space);
	if (!MACH_PORT_VALID(name)) {
		return -EINVAL;
	}

	*out_name = name;
	return 0;
};

int dtape_fileport_makefd(dtape_task_t* task, uint32_t name) {
	ipc_object_t object = IO_NULL;
	ipc_port_t port;
	struct fileglob* fg;
	int fd;

	if (ipc_object_copyin(task->xnu_task.itk_space, name, MACH_MSG_TYPE_COPY_SEND, &object, 0, NULL, IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND) != KERN_SUCCESS) {
		return -EINVAL;
	}
	port = ip_object_to_port(object);

	// the send right keeps the fileglob alive while it's duplicated
	fg = fileport_port_to_fileglob(port);
	fd = fg ? dup(fg->fd) : -1;
	ipc_port_release_send(port);

	if (!fg) {
		return -EINVAL;
	}
	if (fd < 0) {
		return -EMFILE;
	}
	return fd;
};
