schnorr: schnorr.c test.c
	g++ -Wall schnorr.c test.c -lssl -lcrypto -o schnorr

clean:
	$(RM) $(EXE) schnorr *.o

