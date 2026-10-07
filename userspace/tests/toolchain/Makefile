.PHONY: all test diagnostics
all: /tmp/native-c /tmp/native-cpp /tmp/native-threads
/tmp/native-c: hello.c
	gcc -O2 -Wall -Wextra -Werror hello.c -o $@
/tmp/native-cpp: hello.cpp
	g++ -std=c++20 -O2 -Wall -Wextra -Werror hello.cpp -o $@
/tmp/native-threads: threads.cpp
	g++ -std=c++20 -O2 -Wall -Wextra -Werror -pthread threads.cpp -o $@
diagnostics:
	@if gcc -Wall -Wextra -Werror broken.c -o /tmp/should-not-exist > /tmp/compiler-errors 2>&1; then exit 1; fi
	@grep -q 'error:' /tmp/compiler-errors
	@echo NATIVE_DIAGNOSTICS_PASS
test: all diagnostics
	/tmp/native-c
	/tmp/native-cpp
	/tmp/native-threads
