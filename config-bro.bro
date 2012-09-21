##! This script reconfigures some of the builtin Bro scripts to suit certain SecurityOnion uses.

redef PacketFilter::all_packets = F;
redef capture_filters = { ["bpf.conf"] = "ip or not ip" };
