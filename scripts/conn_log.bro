#! Log attribution by extendind conn.log

module osquery::logging::attribution_conn;

# Add attribution fields to the connection log record.
redef record Conn::Info += {
    # Process info on the originating system
    orig_hosts: set[string] &optional &log;
    orig_pids: set[int] &optional &log;
    orig_uids: set[int] &optional &log;
    # Process info on the responsive system
    resp_hosts: set[string] &optional &log;
    resp_pids: set[int] &optional &log;
    resp_uids: set[int] &optional &log;
};

hook osquery::connection_attributing(c: connection, src_attributions: vector of osquery::Attribution, dst_attributions: vector of osquery::Attribution) {
	local attribution: osquery::Attribution;
	local host_id: string;
	local pid: int;
	local uid: int;

	# Originating
	for (a_idx in src_attributions) {
		attribution = src_attributions[a_idx];
		# Host
		host_id = attribution$host_id;
		if (!c$conn?$orig_hosts) { c$conn$orig_hosts = set(host_id); }
		else { add c$conn$orig_hosts[host_id]; }
		
		# PID
		if (attribution?$process_info) {
			pid = attribution$process_info$pid;
			if (!c$conn?$orig_pids) { c$conn$orig_pids = set(pid); }
			else { add c$conn$orig_pids[pid]; }	
		}
		
		# UID
		if (attribution?$user_info) {
			uid = attribution$user_info$uid;
			if (!c$conn?$orig_uids) { c$conn$orig_uids = set(uid); }
			else { add c$conn$orig_uids[uid]; }	
		}
	}

	# Responding
	for (a_idx in dst_attributions) {
		attribution = dst_attributions[a_idx];
		# Host
		host_id = attribution$host_id;
		if (!c$conn?$resp_hosts) { c$conn$resp_hosts = set(host_id); }
		else { add c$conn$resp_hosts[host_id]; }
		
		# PID
		if (attribution?$process_info) {
			pid = attribution$process_info$pid;
			if (!c$conn?$resp_pids) { c$conn$resp_pids = set(pid); }
			else { add c$conn$resp_pids[pid]; }	
		}
		
		# UID
		if (attribution?$user_info) {
			uid = attribution$user_info$uid; 
			if (!c$conn?$resp_uids) { c$conn$resp_uids = set(uid); }
			else { add c$conn$resp_uids[uid]; }	
		}
	}
}
