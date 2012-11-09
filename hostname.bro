module SecurityOnion;

@load base/frameworks/input

export {
	## Event to capture when the hostname is discovered.
	global SecurityOnion::found_hostname: event(hostname: string);

	## Hostname for this box.
	global hostname = "";
}

type HostnameCmdLine: record { s: string; };

event SecurityOnion::hostname_line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	hostname = s;
	system(fmt("rm %s", description$source));
	event SecurityOnion::found_hostname(hostname);
	}

event add_hostname_reader(name: string)
	{
	Input::add_event([$source=name,
	                  $name=name,
	                  $reader=Input::READER_RAW,
	                  $want_record=F,
	                  $fields=HostnameCmdLine,
	                  $ev=SecurityOnion::hostname_line]);
	}

event bro_init() &priority=5
	{
	local tmpfile = "/tmp/bro-hostname-" + unique_id("");
	system(fmt("hostname > %s", tmpfile));
	event add_hostname_reader(tmpfile);
	}