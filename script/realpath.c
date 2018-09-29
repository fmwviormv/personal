#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <util.h>

int main(int argc, char **argv) {
	char *realpath = NULL;
	int fd;
	if (argc != 2) {
		printf("Usage: %s <device id>\n", argv[0]);
		return 0;
	}
	fd = opendev(argv[1], O_RDONLY, OPENDEV_BLCK, &realpath);
	close(fd);
	puts(fd < 0 ? "" : realpath ? realpath : argv[1]);
	return 0;
}
