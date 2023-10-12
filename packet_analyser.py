import argparse
import pyshark
import time

# Create an ArgumentParser object
parser = argparse.ArgumentParser(description="Capture and analyze network packets")

# Add command-line arguments
parser.add_argument("--interface", default="eth0", help="Network interface name")
parser.add_argument("--filter", default="", help="Wireshark display filter")
parser.add_argument("--output", default="", help="Output file name (leave empty to disable)")
parser.add_argument("--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("--count", type=int, default=0, help="Maximum number of packets to capture (0 for unlimited)")
parser.add_argument("--duration", type=float, default=0, help="Maximum duration of capture in seconds (0 for unlimited)")
parser.add_argument("--ring-buffer", type=int, default=0, help="Size of the ring buffer for live capture")
parser.add_argument("--no-promiscuous", action="store_true", help="Disable promiscuous mode")
parser.add_argument("--no-monitor", action="store_true", help="Disable monitor mode")
parser.add_argument("--stop-on-error", action="store_true", help="Stop capture on error")
parser.add_argument("--statistics", action="store_true", help="Display capture statistics")
parser.add_argument("--decode-as", default="", help="Decode a specific dissector as a different protocol")

# Parse command-line arguments
args = parser.parse_args()

# Specify the network interface to capture packets from
interface_name = args.interface
capture = pyshark.LiveCapture(
    interface=interface_name,
    display_filter=args.filter,
    ring_buffer_size=args.ring_buffer,
    promiscuous=not args.no_promiscuous,
    monitor_mode=not args.no_monitor,
    stop_on_malformed=True if args.stop_on_error else False
)

# Initialize variables for timing analysis
previous_packet_time = None
packets_captured = 0
start_time = time.time()

# Open the output file for writing (optional)
output_file = None
if args.output:
    output_file = open(args.output, "w")

# Start capturing packets
for packet in capture.sniff_continuously(packet_count=args.count, timeout=args.duration):
    if 'IP' in packet:
        source_ip = packet.ip.src
        destination_ip = packet.ip.dst
        if args.verbose:
            print(f"Source IP: {source_ip}, Destination IP: {destination_ip}")

    if previous_packet_time:
        current_time = time.time()
        time_difference = current_time - previous_packet_time
        if args.verbose:
            print(f"Time between packets: {time_difference} seconds")

    # Update previous packet time
    previous_packet_time = time.time()

    # Write packet information to the output file (optional)
    if output_file:
        output_file.write(str(packet) + "\n")

    packets_captured += 1

    # Check if the specified capture limit has been reached
    if args.count > 0 and packets_captured >= args.count:
        break

    # Check if the specified capture duration limit has been reached
    if args.duration > 0 and time.time() - start_time >= args.duration:
        break

# Close the output file (optional)
if output_file:
    output_file.close()

# Display capture statistics (optional)
if args.statistics:
    print(f"Packets captured: {packets_captured}")
