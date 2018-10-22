##! Base functionality for NTP messages. 
module NTP;

export {
	## The NTP logging stream identifier.
	redef enum Log::ID += { LOG };

	## The record type which contains the column fields of the NTP log.
	type Info: record {
		ts:		time		&log;
		uid:		string		&log;
		id:		conn_id		&log;
		ref_id:		count		&log &optional;	
		mode:		count		&log &optional;
		mode_name:	string		&log &optional;
		stratum:	count		&log &optional;
		poll:		count		&log &optional;
		precision:	int		&log &optional;
		distance:	interval	&log &optional;
		dispersion:	interval	&log &optional;
		ref_time:	time		&log &optional;
		orig_time:	time		&log &optional;
		rec_time:	time		&log &optional;
		xmt_time:	time		&log &optional;
		excess:		string		&log &optional;
		};

	##  Whether or not to create NTP log stream. 
	global logging: bool =F		&redef; 
		
	## Return mode_name given numeric mode.
	const modes = {
		[0] = "RESERVED",	#Reserved
		[1] = "SYMACT",		#Symetric active
		[2] = "SYMPASS",	#Symetric passive
		[3] = "CLIENT",		#Client
		[4] = "SERVER",		#Server
		[5] = "BROADCAST",	#Broadcast
		[6] = "CONTROL",	#NTP control message
		[7] = "PRIVATE",	#Reserved for private use
	} &default = function(n: count): string {return fmt("mode-%d", n); };
}

# Add NTP information to the connection record.
redef record connection += {
	ntp:       Info  &optional;
};

const ports = { 123/udp,};
redef likely_server_ports += { ports };

# Initialize the NTP logging stream and ports.
event bro_init() &priority=5
	{
	Log::create_stream(NTP::LOG, [$columns=Info, $path="ntp"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);
	}

event ntp_message(c: connection, msg: ntp_msg, excess: string) &priority=5
	{
	local info: Info;
	info$ts			=network_time();
	info$id			=c$id;
	info$uid		=c$uid;
	info$ref_id		=msg$id;
	info$mode		=msg$code;
	info$mode_name		=modes[msg$code];
	info$stratum		=msg$stratum;
	info$poll		=msg$poll;
	info$precision		=msg$precision;
	info$distance		=msg$distance;
	info$dispersion		=msg$dispersion;
	info$ref_time		=msg$ref_t;
	info$orig_time		=msg$originate_t;
	info$rec_time		=msg$receive_t;
	info$xmt_time		=msg$xmit_t;
	info$excess		=excess;
		
	c$ntp = info;
	}

event ntp_message(c: connection, msg: ntp_msg, excess: string)
	{
	if ( logging )
		Log::write(NTP::LOG, c$ntp);
	}
