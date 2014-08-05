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
}

event bro_init()
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
		# If running in standalone mode...
		when ( local nodefile = readfile("/opt/bro/etc/node.cfg") )
			{
			local lines = split_all(nodefile, /\n/);
			for ( i in lines )
				{
				if ( /^[[:blank:]]*#/ in lines[i])
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