.PHONY: all clean build_lib clean_lib

all: build_lib build_ipldecrypt 

clean: clean_ipldecrypt clean_lib 

build_lib:
	make -C libkirk -f Makefile all
	
clean_lib:
	make -C libkirk -f Makefile clean
	
build_ipldecrypt:
	make -C ipl_decrypt -f Makefile all
	
clean_ipldecrypt:
	make -C ipl_decrypt -f Makefile clean
