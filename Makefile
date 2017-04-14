CC=gcc
CFLAGS=
LDFLAGS=

EXE = nat

OBJ = table.o checksum.o

${EXE}: ${OBJ}
	${CC} ${CFLAGS} -o ${EXE} ${OBJ} ${LDFLAGS}

clean:
	rm -f ${EXE} ${OBJ}
