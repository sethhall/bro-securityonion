##! This script is to support the bpf.conf file like other network monitoring tools use.
##! Please don't try to learn from this script right now, there are a large number of
##! hacks in it to work around bugs discovered in Bro.

@load base/frameworks/notice

module BPFConf;

export {
	## The file that is watched on disk for BPF filter changes.
	const filename = "/etc/nsm/rules/bpf.conf" &redef;

	redef enum Notice::Type += { 
		## Invalid filter notice.
		InvalidFilter
	};
}

global filter_parts: vector of string = vector();

type FilterLine: record {
	s: string;
};

global last_line = current_time();
global ignore_lines_until = last_line;

redef enum PcapFilterID += {
	BPFConfPcapFilter,
};


event is_filter_done()
	{
	if ( |filter_parts| > 0 && current_time() - last_line > 5msec )
		{
		local filter = join_string_vec(filter_parts, " ");
		capture_filters["bpf.conf"] = filter;
		
		if ( precompile_pcap_filter(BPFConfPcapFilter, filter) )
			{
			PacketFilter::install();
			}
		else
			{
			NOTICE([$note=InvalidFilter,
			        $msg=fmt("Compiling packet filter from BPF.conf failed"),
			        $sub=filter]);
			Reporter::error(fmt("Bad pcap filter from %s '%s'", filename, filter));
			}

		filter_parts=vector();
		}
	}

event BPFConf::line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	last_line = current_time();
	if ( last_line < ignore_lines_until )
		return;

	local part = sub(s, /[[:blank:]]*#.*$/, "");

	# There is a bug in the input framework where it's reading the file twice the first time.
	# If there is a duplicate line, this avoids rereading it.
	if ( |filter_parts| > 0 && filter_parts[0] == part )
		{
		ignore_lines_until = last_line + 2secs;
		return;
		}
	
	# We don't want any blank parts.
	if ( part != "" )
		filter_parts[|filter_parts|] = part;

	schedule 2secs { is_filter_done() };
	}

event bro_init() &priority=5
	{
	if ( BPFConf::filename != "" )
		{
		Input::add_event([$source=BPFConf::filename,
		                  $name="bpfconf",
		                  $reader=Input::READER_RAW,
		                  $mode=Input::REREAD,
		                  $want_record=F,
		                  $fields=FilterLine,
		                  $ev=BPFConf::line]);
		}
	}
