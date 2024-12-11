all: AntiVirus

AntiVirus: AntiVirus.c
	gcc -g -Wall -m32 -o $@ $<

.PHONY: clean
clean:
	rm -f AntiVirus