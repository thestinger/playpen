CXX = clang++
CXXFLAGS = -std=c++11 -O2 -Wmost
LDLIBS = -lseccomp
LDFLAGS = -Wl,--as-needed

playpen: playpen.cc
