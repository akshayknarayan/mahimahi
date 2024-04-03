#ifndef RUST_PACKET_QUEUE_HH
#define RUST_PACKET_QUEUE_HH

#include "abstract_packet_queue.hh"
#include "rustq.rs.hh"

class RustPacketQueue : public AbstractPacketQueue
{
private:
    const std::string& type;
    const std::string& args;
    rust::Box<WrapperPacketQueue> inner_;

public:
    RustPacketQueue( const std::string & type, const std::string & args );

    void enqueue( QueuedPacket && p ) override;
    QueuedPacket dequeue( void ) override;
    bool empty( void ) const override;

    unsigned int size_bytes( void ) const override;
    unsigned int size_packets( void ) const override;

    void set_bdp( int bytes ) override;

    std::string to_string( void ) const override;
};

#endif
