CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall

all: example selftest

example: example.cpp bdd_client.hpp bdd_crypto.hpp
	$(CXX) $(CXXFLAGS) example.cpp -o example

selftest: selftest.cpp bdd_crypto.hpp
	$(CXX) $(CXXFLAGS) selftest.cpp -o selftest

test: selftest
	./selftest

clean:
	rm -f example selftest

.PHONY: all test clean
