#!/bin/sh

if [ -e /usr/include/openssl/engine.h ]; then
    echo Building dntest ENGINE
    gcc -fPIC -o e_dntest.o -c e_dntest.c
    ld -shared --no-undefined --build-id -lcrypto -lc -o dntest.so e_dntest.o
fi
