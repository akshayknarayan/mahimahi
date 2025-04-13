AM_CPPFLAGS = -I$(srcdir)/../util $(CXX20_FLAGS)
AM_CXXFLAGS = $(PICKY_CXXFLAGS)
#CXXBRIDGE = cxxbridge
#CARGO = cargo

noinst_LIBRARIES = libpacket.a librustqbindings.a rustq/target/release/librustq.a

rustq.rs.hh rustq.rs.cc: rustq/src/lib.rs
	$(CXXBRIDGE) $< --header > rustq.rs.hh
	$(CXXBRIDGE) $< > rustq.rs.cc

rustq/target/release/librustq.a: rustq/src/lib.rs rustq/Cargo.toml
	cd rustq && $(CARGO) build --release

# remove -Weffc++ for these sources because cxxbridge's generated bindings don't use initializer lists.
librustqbindings_a_SOURCES = rustq.rs.cc rustq.rs.hh rust_packet_queue.cc rust_packet_queue.hh
librustqbindings_a_CXXFLAGS = $(filter-out -Weffc++,$(AM_CXXFLAGS))

libpacket_a_SOURCES = packetshell.hh packetshell.cc queued_packet.hh \
                      abstract_packet_queue.hh dropping_packet_queue.hh dropping_packet_queue.cc infinite_packet_queue.hh \
                      drop_tail_packet_queue.hh drop_head_packet_queue.hh \
                      codel_packet_queue.cc codel_packet_queue.hh \
                      pie_packet_queue.cc pie_packet_queue.hh \
					  ecmp_packet_queue.cc ecmp_packet_queue.hh \
					  fair_packet_queue.cc fair_packet_queue.hh \
                      bindworkaround.hh
