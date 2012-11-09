module SecurityOnion;

@load base/frameworks/input
@load base/frameworks/cluster

export {
	## Event to capture when the interface is discovered.
	global SecurityOnion::found_interface: event(inter: string);

	## Interface being sniffed.
	global interface = "";
}

type InterfaceCmdLine: record { s: string; };

event SecurityOnion::interface_line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local parts = split_all(s, /[[:blank:]]*=[[:blank:]]*/);
	if ( 3 in parts )
		{
		interface = parts[3];
		system(fmt("rm %s", description$source));
		event SecurityOnion::found_interface(interface);
		}
	}

event add_interface_reader(name: string)
	{
	Input::add_event([$source=name,
	                  $name=name,
	                  $reader=Input::READER_RAW,
	                  $want_record=F,
	                  $fields=InterfaceCmdLine,
	                  $ev=SecurityOnion::interface_line]);
	}

event bro_init() &priority=5
	{
	local peer = get_event_peer()$descr;
	if ( peer in Cluster::nodes && Cluster::nodes[peer]?$interface )
		{
		interface = Cluster::nodes[peer]$interface;
		event SecurityOnion::found_interface(interface);
		return;
		}
	else
		{
		local tmpfile = "/tmp/bro-interface-" + unique_id("");
		
		system(fmt("grep \"interface\" ../bro.work8/aux/broctl/etc/node.cfg 2>/dev/null | grep -v \"^[[:blank:]]*#\" > %s", tmpfile));

		#system(fmt("grep \"interface\" /opt/bro/etc/node.cfg 2>/dev/null | grep -v \"^[[:blank:]]*#\" > %s", tmpfile));
		event add_interface_reader(tmpfile);
		}
	}
