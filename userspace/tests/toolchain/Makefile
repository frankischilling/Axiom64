.PHONY: all test diagnostics
all: /tmp/native-c /tmp/native-cpp /tmp/native-threads /tmp/native-library.so /tmp/native-shared
/tmp/native-arithmetic.o: arithmetic.asm
	nasm -f elf64 $< -o $@
/tmp/native-c: hello.c /tmp/native-arithmetic.o
	gcc -O2 -Wall -Wextra -Werror $^ -o $@
/tmp/native-cpp: hello.cpp
	g++ -std=c++20 -O2 -Wall -Wextra -Werror hello.cpp -o $@
/tmp/native-threads: threads.cpp
	g++ -std=c++20 -O2 -Wall -Wextra -Werror -pthread threads.cpp -o $@
/tmp/native-library.so: library.cpp
	g++ -std=c++20 -O2 -Wall -Wextra -Werror -fPIC -shared -Wl,-z,defs $< -o $@
/tmp/native-shared: shared.cpp
	g++ -std=c++20 -O2 -Wall -Wextra -Werror -pthread $< -o $@ -ldl
diagnostics:
	@if gcc -Wall -Wextra -Werror broken.c -o /tmp/should-not-exist > /tmp/compiler-errors 2>&1; then exit 1; fi
	@grep -q 'error:' /tmp/compiler-errors
	@echo NATIVE_DIAGNOSTICS_PASS
test: all diagnostics
	/tmp/native-c
	/tmp/native-cpp
	/tmp/native-threads
	/tmp/native-shared /tmp/native-library.so
