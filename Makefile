all:
	cd gnu-efi; make; make bootloader
	cd kernel; make buildimg; make

run:
	cd kernel; make run
