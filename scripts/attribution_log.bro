#! Logs host network attribution.

module osquery::logging::attribution;

export {
	# Logging
        redef enum Log::ID += { LOG };

        type Info: record {
		conn_id: string &log;
		isOrig: bool &log;
                host: string &log;
		pid: int &log &optional;
		path: string &log &optional;
		cmdline: string &log &optional;
		parent: int &log &optional;
                uid: int &log &optional;
		username: string &log &optional;
		user_type: string &log &optional;
        };
}

event osquery::connection_attributed(c: connection, src_attributions: vector of osquery::Attribution, dst_attributions: vector of osquery::Attribution) {
	local attribution: osquery::Attribution;
	local info: Info;

	# Originating
	for (a_idx in src_attributions) {
		attribution = src_attributions[a_idx];
		info = [$conn_id=c$uid, $isOrig=T, $host=attribution$host_id];

		if (attribution?$process_info) {
			info$pid = attribution$process_info$pid;
			if (attribution$process_info?$path) { 
				info$path = attribution$process_info$path; }
			if (attribution$process_info?$cmdline) { 
				info$cmdline = attribution$process_info$cmdline; }
			if (attribution$process_info?$parent) { 
				info$parent = attribution$process_info$parent; }
		}
		if (attribution?$user_info) {
			info$uid = attribution$user_info$uid;
			if (attribution$user_info?$username) { 
				info$username = attribution$user_info$username; }
			if (attribution$user_info?$user_type) { 
				info$user_type = attribution$user_info$user_type; }
		}

        	Log::write(LOG, info);
	}

	# Responding
	for (a_idx in dst_attributions) {
		attribution = dst_attributions[a_idx];
		info = [$conn_id=c$uid, $isOrig=F, $host=attribution$host_id];

		if (attribution?$process_info) {
			info$pid = attribution$process_info$pid;
			if (attribution$process_info?$path) { 
				info$path = attribution$process_info$path; }
			if (attribution$process_info?$cmdline) { 
				info$cmdline = attribution$process_info$cmdline; }
			if (attribution$process_info?$parent) { 
				info$parent = attribution$process_info$parent; }
		}
		if (attribution?$user_info) {
			info$uid = attribution$user_info$uid;
			if (attribution$user_info?$username) { 
				info$username = attribution$user_info$username; }
			if (attribution$user_info?$user_type) { 
				info$user_type = attribution$user_info$user_type; }
		}

        	Log::write(LOG, info);
	}


}

event bro_init() {
        Log::create_stream(LOG, [$columns=Info, $path="osq-attribution"]);
}
