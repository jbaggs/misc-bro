##! Notify on NTP command modes
@load base/frameworks/notice
@load base/utils/directions-and-hosts

module NTP;

export {
	redef enum Notice::Type += { Restricted_Mode };

	## Restrict control & private modes
	const restricted_modes = [6,7] &redef;

	## A table of servers that are allowed type 6 (control) queries, 
	## and the hosts that are allowed to connect to them.
	const allowed_control: table[addr] of set[addr] &redef;

	## Whether or not outbound traffic is subject to restrictions
	const  restricted_outbound = F &redef;
}

# Tests for connections that are exempt from mode restrictions
function allowed_conn(c: connection) : bool
	{
	if ( c$ntp$mode == 6 && c$id$resp_h in allowed_control
		&& c$id$orig_h in allowed_control[c$id$resp_h] )
		return T;
	else if (! restricted_outbound && 
		 id_matches_direction(c$id,OUTBOUND) )
		return T;
	else
		return F;
	}

event ntp_message(c: connection, msg: ntp_msg, excess: string)
	{
	if ( c$ntp$mode in restricted_modes && ! allowed_conn(c) )
		{
		NOTICE([$note = Restricted_Mode,
			$conn=c,
			$msg = fmt("Mode %s \"%s\" query.", c$ntp$mode, c$ntp$mode_name),
			$sub = excess,
			$identifier = cat(c$id$orig_h,c$id$resp_h)
			]);
		}
	}
