#include <sys/ioctl.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <util.h>

void	 AtExit(void);
FILE	*pty;
int	 pty_fd, tty_fd;

int
main(void)
{
	int	 ch, on = 1;

	atexit(AtExit);
	if (openpty(&pty_fd, &tty_fd, NULL, NULL, NULL) < 0)
		err(1, "openpty");
	if (ioctl(tty_fd, TIOCCONS, &on) < 0)
		err(1, "ioctl");
	if ((pty = fdopen(pty_fd, "r")) == NULL)
		err(1, "fdopen");
	while ((ch = fgetc(pty)) != EOF) {
		putchar('\a');
		putchar(ch);
	}
	return 0;
}

void
AtExit(void)
{
	pty && fclose(pty);
	pty_fd && close(pty_fd);
	tty_fd && close(tty_fd);
	putchar('\a');
}
