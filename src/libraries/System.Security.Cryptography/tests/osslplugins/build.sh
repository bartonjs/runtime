#!/bin/sh

if [ -e /usr/include/openssl/engine.h ]; then
    echo Building dntest ENGINE
    clang -fPIC -o e_dntest.o -c e_dntest.c &&
        ld -shared --no-undefined --build-id -lcrypto -lc -o dntest.so e_dntest.o &&
        echo dntest ENGINE built successfully!
else
    echo Cannot build dntest ENGINE, missing engine.h
fi

if [ -e /usr/include/openssl/provider.h ]; then
    echo Building dntestprov Provider
    clang -fPIC -o p_dntestprov.o -c p_dntestprov.c &&
        ld -shared --no-undefined --build-id -lcrypto -lc -o dntestprov.so p_dntestprov.o &&
	echo dntestprov Provider built successfully!
else
    echo Cannot build dntestprov Provider, missing provider.h
fi
