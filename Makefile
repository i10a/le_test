PROG=le_test
SRCS=le_test.c /usr/src/usr.sbin/bluetooth/hccontrol/send_recv.c
LDADD=-lbluetooth
NO_MAN=yes
CFLAGS=-Wall

.include <bsd.prog.mk>
