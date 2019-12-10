CXX ?= g++
LAB_ROOT ?= ../..
BACKEND ?= LINUX
CXXFLAGS ?= --std=c++11 -I $(LAB_ROOT)/HAL/include -DROUTER_BACKEND_$(BACKEND)
LDFLAGS ?= -lpcap

.PHONY: all clean
all: router.out

clean:
	rm -f *.o *.out

hal.o: $(LAB_ROOT)/HAL/src/linux/router_hal.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

router.out: main.cpp hal.o
	$(CXX) -Wconversion -Wall -Wextra $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
