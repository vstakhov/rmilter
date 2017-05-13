# A simple makefile to generate documentation from .md using pandoc

PANDOC ?= pandoc

all: man

man: rmilter.8

rmilter.8: rmilter.8.md
	$(PANDOC) -s -f markdown -t man -o rmilter.8 rmilter.8.md
