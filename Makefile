#!/bin/bash
AES_GCM=aes_gcm.c aes_gcm.h
DH=DH.c DH.h
AES=aes.c aes.h
all:mitm.c DHServer.c DHClient.c ${AES} ${DH} ${AES_GCM}
#	gcc mitm.c ${AES} ${DH} -o mitm -lcrypto
	gcc DHServer.c ${AES} ${DH} ${AES_GCM} -o DHS -lcrypto
	gcc DHClient.c ${AES} ${DH} ${AES_GCM} -o DHC -lcrypto	
S:DHServer.c ${AES} ${DH} ${AES_GCM}
	gcc DHServer.c ${AES} ${DH} ${AES_GCM} -o DHS -lcrypto
C:DHClient.c ${DH} ${AES_GCM}
	gcc DHClient.c ${DH} ${AES_GCM} -o DHC -lcrypto
#M:mitm.c ${AES} ${DH}
#	gcc mitm.c ${AES} ${DH} -o mitm -lcrypto
M:mitm.c
	gcc mitm.c -o mitm -lcrypto
clean:
	rm -f mitm
	rm -f DHC
	rm -f DHS  
