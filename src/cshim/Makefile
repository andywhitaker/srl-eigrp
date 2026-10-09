CC ?= gcc
CXX ?= g++
AR ?= ar
CFLAGS ?= -O2 -g -fPIC -std=c11 -Wall -Wextra -pthread
CXXFLAGS ?= -O2 -g -fPIC -std=c++17 -Wall -Wextra -pthread
CPPFLAGS ?= -I../upstream/eigrp/eigrp/code -I../../upstream/eigrp/eigrp/code -I.

CSRCS := srl_cshim_sys.c srl_cshim_netns.c srl_cshim_rib.c srl_cshim_overrides.c
CXXSRCS := srl_cshim_crypto.cpp
OBJS := $(CSRCS:.c=.o) $(CXXSRCS:.cpp=.o)

all: libsrl-cshim.a

libsrl-cshim.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) libsrl-cshim.a
