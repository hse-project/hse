CC=gcc -g

_LIBS := libhse_kvdb.so

LIBS := $(_LIBS:lib%=-l:lib%)

DEPS = $(LIBS) $(CONS_DES) -luuid -lcrypto -lpthread -lmicrohttpd -lmpool-blkid -lm -lurcu-bp -lurcu-common -lmpool

all: ex1_create ex2_simple_ops ex3_cursor ex4_transactions ex5_large_val

ex1_create: ex1_create.c
	$(CC) -o ex1_create ex1_create.c $(DEPS)

ex2_simple_ops: ex2_simple_ops.c
	$(CC) -o ex2_simple_ops ex2_simple_ops.c $(DEPS)

ex3_cursor: ex3_cursor.c
	$(CC) -o ex3_cursor ex3_cursor.c $(DEPS)

ex4_transactions: ex4_transactions.c
	$(CC) -o ex4_transactions ex4_transactions.c $(DEPS)

ex5_large_val: ex5_large_val.c
	$(CC) -o ex5_large_val ex5_large_val.c $(DEPS)

clean:
	rm -f ./ex1_create
	rm -f ./ex2_simple_ops
	rm -f ./ex3_cursor
	rm -f ./ex4_transactions
	rm -f ./ex5_large_val
