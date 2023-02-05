#!/bin/env bash

export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu/
export CGO_CFLAGS=-I/usr/include

go install
