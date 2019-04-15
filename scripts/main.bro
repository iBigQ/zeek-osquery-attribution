#! Attribution of network connections to hosts, processes and users

@load zeek-osquery-state/interfaces
@load zeek-osquery-state/users
@load zeek-osquery-host-conn

module osquery;

export {
	type Attribution: record {
		host_id: string;
		process_info: ProcessInfo &optional;
		socket_info: SocketInfo &optional;
		user_info: UserInfo &optional;
	};

	global connection_attributing: hook(c: connection, src_attributions: vector of Attribution, dst_attributions: vector of Attribution);
	
	global connection_attributed: event(c: connection, src_attributions: vector of Attribution, dst_attributions: vector of Attribution);
}

function attribute_connection(c: connection) {
	# Check the origin of the connection
	# - Get list of hosts with this source IP
	local src_host_ids = getHostIDsByAddress(c$id$orig_h);
	# - Get list of hosts with this target IP
	local dst_host_ids = getHostIDsByAddress(c$id$resp_h);

	if (|src_host_ids| + |dst_host_ids| == 0) {
		return;
	}
	
	local process_connections: set[ProcessConnectionInfo] = set();
	local src_attributions: vector of Attribution = vector();
	local dst_attributions: vector of Attribution = vector();
	local attribution: Attribution;
	local process_info: ProcessInfo;
	local socket_info: SocketInfo;
	local user_info: UserInfo;
	local candidate_users: vector of UserInfo;

	# - Lookup if any of the source candidates connected to the target
	for (host_id in src_host_ids) {

		# Process Connections
		process_connections = getProcessConnectionInfosByHostIDByConn(host_id, c);
		if (|process_connections| == 0) {
			# Host only
			attribution = [$host_id=host_id];
			src_attributions += attribution;
			next;
		}

		# Iterate Process Connections
		for (proc_conn in process_connections) {
			process_info = proc_conn$process_info;
			socket_info = proc_conn$socket_info;

			# Find user
			candidate_users = getUserInfoByHostID(host_id, process_info$uid);
			if (|candidate_users| == 0) {
				# Host + Process + Socket
				attribution = [$host_id=host_id, $process_info=process_info, $socket_info=socket_info];
				src_attributions += attribution;
				next;
			}

			for (u_idx in candidate_users) {
				# Host + Process + Socket + User
				user_info = candidate_users[u_idx];
				attribution = [$host_id=host_id, $process_info=process_info, $socket_info=socket_info, $user_info=user_info];
				src_attributions += attribution;
			}
		}
	}

	# - Lookup if any of the target candidates bound on the target port
	for (host_id in dst_host_ids) {

		# Process Connections
		process_connections = getProcessConnectionInfosByHostIDByConn(host_id, c, F);
		if (|process_connections| == 0) {
			# Host only
			attribution = [$host_id=host_id];
			dst_attributions += attribution;
			next;
		}

		# Iterate Process Connections
		for (proc_conn in process_connections) {
			process_info = proc_conn$process_info;
			socket_info = proc_conn$socket_info;

			# Find user
			candidate_users = getUserInfoByHostID(host_id, process_info$uid);
			if (|candidate_users| == 0) {
				# Host + Process + Socket
				attribution = [$host_id=host_id, $process_info=process_info, $socket_info=socket_info];
				dst_attributions += attribution;
				next;
			}

			for (u_idx in candidate_users) {
				# Host + Process + Socket + User
				user_info = candidate_users[u_idx];
				attribution = [$host_id=host_id, $process_info=process_info, $socket_info=socket_info, $user_info=user_info];
				dst_attributions += attribution;
			}
		}
	}

	hook osquery::connection_attributing(c, src_attributions, dst_attributions);
	event osquery::connection_attributed(c, src_attributions, dst_attributions);

}

event connection_state_remove(c: connection)
{
    attribute_connection(c);
}
