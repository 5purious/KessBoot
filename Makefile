all:
	cd gnu-efi; make; make bootloader
	cd kernel; make buildimg; make

setup:
	cd kernel; make setup

run:
	cd kernel; make run
