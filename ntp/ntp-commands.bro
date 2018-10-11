##! Notify on NTP command modes (control or private)

module NTP;

export {
	redef enum Notice::Type += { Restricted_Mode };
}

event ntp_message(c: connection, msg: ntp_msg, excess: string)
	{
	if (( c$ntp$mode == 6 ) || ( c$ntp$mode == 7))
		{
		NOTICE([$note = Restricted_Mode,
			$conn=c,
			$msg = fmt("Mode %s \"%s\" query.", c$ntp$mode, c$ntp$mode_name),
			$sub = excess,
			$identifier = cat(c$id$orig_h,c$id$resp_h)
			]);
		}
	}
