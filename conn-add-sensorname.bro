@load ./hostname
@load ./interface

redef record Conn::Info += {
	sensorname: string &log &optional;
};

event connection_state_remove(c: connection)
	{
	local sensorname = cat(SecurityOnion::hostname, "-", SecurityOnion::interface);
	c$conn$sensorname = sensorname;
	}

