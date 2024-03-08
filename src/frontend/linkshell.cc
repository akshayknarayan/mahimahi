/* -*-mode:c++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <getopt.h>

#include "infinite_packet_queue.hh"
#include "drop_tail_packet_queue.hh"
#include "drop_head_packet_queue.hh"
#include "codel_packet_queue.hh"
#include "pie_packet_queue.hh"
#include "ecmp_packet_queue.hh"
#include "fair_packet_queue.hh"
#include "link_queue.hh"
#include "packetshell.cc"
#include "util.hh"

using namespace std;

void usage_error( const string & program_name )
{
    cerr << "Usage: " << program_name << " UPLINK-TRACE DOWNLINK-TRACE [OPTION]... [COMMAND]" << endl;
    cerr << endl;
    cerr << "Options = --once" << endl;
    cerr << "          --uplink-log=FILENAME --downlink-log=FILENAME" << endl;
    cerr << "          --meter-uplink --meter-uplink-delay" << endl;
    cerr << "          --meter-downlink --meter-downlink-delay" << endl;
    cerr << "          --meter-all" << endl;
    cerr << "          --uplink-queue=QUEUE_TYPE --downlink-queue=QUEUE_TYPE" << endl;
    cerr << "          --uplink-queue-args=QUEUE_ARGS --downlink-queue-args=QUEUE_ARGS" << endl;
    cerr << "          --both=QUEUE_TYPE,QUEUE_ARGS" << endl;
    cerr << "          --cbr" << endl;
    cerr << "                (if --cbr is used, UPLINK-TRACE and DOWNLINK-TRACE should be desired bitrate" << endl;
    cerr << "                 rather than filename, expressed as \"XK\" for X Kbps or \"XM\" for X Mbps)" << endl;
    cerr << endl;
    cerr << "          QUEUE_TYPE = infinite | droptail | drophead | codel | pie | ecmp | akshayfq" << endl;
    cerr << "          QUEUE_ARGS = \"NAME=NUMBER[, NAME2=NUMBER2, ...]\"" << endl;
    cerr << "              (with NAME = bytes | packets | target | interval | qdelay_ref | max_burst)" << endl;
    cerr << "                  target, interval, qdelay_ref, max_burst are in milli-second" << endl << endl;
    cerr << "           Additional QUEUE_ARGS for ECMP only:" << endl;
    cerr << "             * queues            : number of internal queues" << endl;
    cerr << "             * workconserving    : 1 = wc, 0 = not wc" << endl;
    cerr << "             * perflow           : 1 = per-flow balancing, 0 = per-packet spraying" << endl;
    cerr << "             * seed              : seed for pRNG, only needed for delay jitter" << endl;
    cerr << "             * mean_jitter       : mean of poisson process for calculating delay jitter, if 0, no jitter" << endl;

    throw runtime_error( "invalid arguments" );
}

unique_ptr<AbstractPacketQueue> get_packet_queue( const string & type, const string & args, const string & program_name )
{
    if ( type == "infinite" ) {
        return unique_ptr<AbstractPacketQueue>( new InfinitePacketQueue( args ) );
    } else if ( type == "droptail" ) {
        return unique_ptr<AbstractPacketQueue>( new DropTailPacketQueue( args ) );
    } else if ( type == "drophead" ) {
        return unique_ptr<AbstractPacketQueue>( new DropHeadPacketQueue( args ) );
    } else if ( type == "codel" ) {
        return unique_ptr<AbstractPacketQueue>( new CODELPacketQueue( args ) );
    } else if ( type == "pie" ) {
        return unique_ptr<AbstractPacketQueue>( new PIEPacketQueue( args ) );
    } else if ( type == "ecmp" ) {
        return unique_ptr<AbstractPacketQueue>( new ECMPPacketQueue( args ) );
    } else if ( type == "akshayfq" ) {
        return unique_ptr<AbstractPacketQueue>( new FairPacketQueue( args ) );
    } else {
        cerr << "Unknown queue type: " << type << endl;
    }

    usage_error( program_name );

    return nullptr;
}

string shell_quote( const string & arg )
{
    string ret = "'";
    for ( const auto & ch : arg ) {
        if ( ch != '\'' ) {
            ret.push_back( ch );
        } else {
            ret += "'\\''";
        }
    }
    ret += "'";

    return ret;
}

int main( int argc, char *argv[] )
{
    try {
        const bool passthrough_until_signal = getenv( "MAHIMAHI_PASSTHROUGH_UNTIL_SIGNAL" );

        /* clear environment while running as root */
        char ** const user_environment = environ;
        environ = nullptr;

        check_requirements( argc, argv );

        if ( argc < 3 ) {
            usage_error( argv[ 0 ] );
        }

        string command_line { shell_quote( argv[ 0 ] ) }; /* for the log file */
        for ( int i = 1; i < argc; i++ ) {
            command_line += string( " " ) + shell_quote( argv[ i ] );
        }

        const option command_line_options[] = {
            { "uplink-log",           required_argument, nullptr, 'u' },
            { "downlink-log",         required_argument, nullptr, 'd' },
            { "once",                       no_argument, nullptr, 'o' },
            { "meter-uplink",               no_argument, nullptr, 'm' },
            { "meter-downlink",             no_argument, nullptr, 'n' },
            { "meter-uplink-delay",         no_argument, nullptr, 'x' },
            { "meter-downlink-delay",       no_argument, nullptr, 'y' },
            { "meter-all",                  no_argument, nullptr, 'z' },
            { "uplink-queue",         required_argument, nullptr, 'q' },
            { "downlink-queue",       required_argument, nullptr, 'w' },
            { "uplink-queue-args",    required_argument, nullptr, 'a' },
            { "downlink-queue-args",  required_argument, nullptr, 'b' },
            { "both",                 optional_argument, nullptr, 'e' },     
            { "cbr",                        no_argument, nullptr, 'c' },
            { 0,                                      0, nullptr, 0 }
        };

        string uplink_logfile, downlink_logfile;
        bool repeat = true;
        bool meter_uplink = false, meter_downlink = false;
        bool meter_uplink_delay = false, meter_downlink_delay = false;
        bool constant_bitrate_trace = false;
        string uplink_queue_type = "infinite", downlink_queue_type = "infinite",
               uplink_queue_args, downlink_queue_args;

        while ( true ) {
            const int opt = getopt_long( argc, argv, "u:d:", command_line_options, nullptr );
            if ( opt == -1 ) { /* end of options */
                break;
            }

            switch ( opt ) {
            case 'u':
                uplink_logfile = optarg;
                break;
            case 'd':
                downlink_logfile = optarg;
                break;
            case 'o':
                repeat = false;
                break;
            case 'm':
                meter_uplink = true;
                break;
            case 'n':
                meter_downlink = true;
                break;
            case 'x':
                meter_uplink_delay = true;
                break;
            case 'y':
                meter_downlink_delay = true;
                break;
            case 'z':
                meter_uplink = meter_downlink
                    = meter_uplink_delay = meter_downlink_delay
                    = true;
                break;
            case 'q':
                uplink_queue_type = optarg; 
                break;
            case 'w':
                downlink_queue_type = optarg;
                break;
            case 'a':
                uplink_queue_args = optarg;
                break;
            case 'b':
                downlink_queue_args = optarg;
                break;
            case 'e': { 
                //const char *oa = optarg;
                char *p = strchr(optarg, ',');
                *p = '\0';
                uplink_queue_type = downlink_queue_type = optarg;
                uplink_queue_args = downlink_queue_args = (p+1);
                break; }
            case 'c':
                constant_bitrate_trace = true;
                break;
            case '?':
                cerr << "Unknown arguemnt" << endl;
                usage_error( argv[ 0 ] );
                break;
            default:
                throw runtime_error( "getopt_long: unexpected return value " + to_string( opt ) );
            }
        }

        if ( optind + 1 >= argc ) {
            usage_error( argv[ 0 ] );
        }

        string uplink_filename = argv[ optind ];
        string downlink_filename = argv[ optind + 1 ];

        unique_ptr<AbstractPacketQueue> uplink_packet_queue = 
            get_packet_queue( uplink_queue_type, uplink_queue_args, argv[ 0 ] );

        unique_ptr<AbstractPacketQueue> downlink_packet_queue = 
            get_packet_queue( downlink_queue_type, downlink_queue_args, argv[ 0 ] );

        if (constant_bitrate_trace) {
            int delay = 0;
            for ( int i = 1; i < argc; i++ ) {
                if (string(argv[i]).find("mm-delay") != string::npos) {
                    delay = stoi(string(argv[i+1]));
                    break;
                }
            }
            if ( delay > 0 ) {
                double uplink_bdp = bdp_bytes( str_to_mbps( uplink_filename ), delay );
                double downlink_bdp = bdp_bytes( str_to_mbps( uplink_filename ), delay );
                cout << "Uplink   BDP:\t" << uplink_bdp << "b\t(" << round(uplink_bdp / 1500) << "p)" << endl;
                cout << "Downlink BDP:\t" << downlink_bdp << "b\t(" << round(downlink_bdp / 1500) << "p)" << endl;
                uplink_packet_queue->set_bdp( round( uplink_bdp ) );
                downlink_packet_queue->set_bdp( round( downlink_bdp ) );
            }

            uplink_filename = get_cbr_trace( uplink_filename );
            downlink_filename = get_cbr_trace( downlink_filename );
        }

        vector<string> command;

        if ( optind + 2 == argc ) {
            command.push_back( shell_path() );
        } else {
            for ( int i = optind + 2; i < argc; i++ ) {
                command.push_back( argv[ i ] );
            }
        }

        PacketShell<LinkQueue> link_shell_app( "link", user_environment, passthrough_until_signal );

        link_shell_app.start_uplink( "[link] ", command,
                                     "Uplink", uplink_filename, uplink_logfile, repeat, meter_uplink, meter_uplink_delay,
                                     uplink_packet_queue,
                                     command_line );

        link_shell_app.start_downlink( "Downlink", downlink_filename, downlink_logfile, repeat, meter_downlink, meter_downlink_delay,
                                       downlink_packet_queue,
                                       command_line );

        return link_shell_app.wait_for_exit();
    } catch ( const exception & e ) {
        print_exception( e );
        return EXIT_FAILURE;
    }
}
