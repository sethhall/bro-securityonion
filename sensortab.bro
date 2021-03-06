@load ./readfile

module SecurityOnion;

@load base/frameworks/input
@load base/frameworks/cluster

export {
	## Event to capture when the interface is discovered.
	global SecurityOnion::found_interface: event(inter: string);

	## Event to capture when the interface is discovered.
	global SecurityOnion::found_sensorname: event(name: string);

	## Interface being sniffed.
	global interface = "";

	## Name of the sensor.
	global sensorname = "";

	## The filename where the sensortab is located.
	const sensortab_file = "/opt/bro/etc/node.cfg" &redef;
}

event bro_init()
	{
	if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER ) 
		{
		local node = Cluster::node;
		if ( node in Cluster::nodes && Cluster::nodes[node]?$interface )
			{
			interface = Cluster::nodes[node]$interface;
			event SecurityOnion::found_interface(interface);
			}
		}
	else
		{
		# If running in standalone mode...
		when ( local nodefile = readfile(sensortab_file) )
			{
			local lines = split_all(nodefile, /\n/);
			for ( i in lines )
				{
				if ( /^[[:blank:]]*#/ in lines[i] )
					next;

				local fields = split_all(lines[i], /[[:blank:]]*=[[:blank:]]*/);
				if ( 3 in fields && fields[1] == "interface" )
					{
					interface = fields[3];
					event SecurityOnion::found_interface(interface);
					}
				}
			}
		}
	}

event SecurityOnion::found_interface(interface: string)
	{
	when ( local r = readfile("/etc/nsm/sensortab") )
		{
		local lines = split_all(r, /\n/);
		for ( i in lines )
			{
			local fields = split_all(lines[i], /\t/);
			if ( 7 !in fields )
				next;

			local name = fields[1];
			local iface = fields[7];
			
			if ( SecurityOnion::iface == interface )
				{
				#print "Sensorname: " + sensor_name + " -- Interface: " + sensor_interface;
				sensorname = name;
				event SecurityOnion::found_sensorname(sensorname);
				}
			}
		}
	}
