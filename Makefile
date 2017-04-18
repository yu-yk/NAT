CC=gcc
CFLAGS=
LDFLAGS=-lnetfilter_queue

EXE = nat

OBJ = table.o checksum.o

${EXE}: ${OBJ}
	${CC} nat.c ${CFLAGS} -o ${EXE} ${OBJ} ${LDFLAGS}

clean:
	rm -f ${EXE} ${OBJ}
