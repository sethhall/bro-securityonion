
event bro_init()
	{
	if ( ! reading_live_traffic() )
		return;

	Log::remove_default_filter(HTTP::LOG);
	Log::add_filter(HTTP::LOG, [$name = "http-interfaces",
	                            $path_func(id: Log::ID, path: string, rec: HTTP::Info) = 
	                            	{ 
	                            	local node = Cluster::node;
	                            	if ( node in Cluster::nodes && Cluster::nodes[node]?$interface )
	                            		return cat(path, "_", Cluster::nodes[node]$interface);
	                            	else
	                            		return path;
	                            	}
	                            ]);
	}