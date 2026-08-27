export type APIResponse<T = undefined> = {
	message?: string;
	data?: T;
};

export type APIErrorResponse = APIResponse<undefined> & {
	message: string;
};

export class APIError extends Error {
	status: number;
	statusText: string;
	responseMessage: string;

	constructor(status: number, statusText: string, responseMessage = "") {
		super(responseMessage || `${status}: ${statusText}`);
		this.name = "APIError";
		this.status = status;
		this.statusText = statusText;
		this.responseMessage = responseMessage;
	}
}

export function getErrorMessage(error: unknown): string {
	if (error instanceof APIError) {
		return error.responseMessage || error.statusText;
	}

	if (error instanceof Error) {
		return error.message;
	}

	return "Unknown error";
}

export type CSREntry = {
	id: number;
	csr: string;
	certificate_chain: string;
	status: "Outstanding" | "Active" | "Rejected" | "Revoked";
	email: string;
};

export type CertificateSigningRequest = {
	commonName?: string;
	stateOrProvince?: string;
	OrganizationalUnitName?: string;
	organization?: string;
	emailAddress?: string;
	country?: string;
	locality?: string;
	sansDns: string[];
	sansIp: string[];
	is_ca: boolean;
};

export type CertificateAuthorityEntry = {
	id: number;
	enabled: boolean;
	certificate: string;
	csr: string;
	crl: string;
};

export enum RoleID {
	Admin = 0,
	CertificateManager = 1,
	CertificateRequestor = 2,
	ReadOnly = 3,
}

export type User = {
	exp: number;
	id: number;
	role_id: RoleID;
	email: string;
	activeCA: number;
};

export type UserEntry = {
	id: number;
	email: string;
	role_id: RoleID;
};

export type ConfigEntry = {
	port: number;
	pebble_notifications: boolean;
	logging_level: string;
	logging_output: string;
	encryption_backend_type: string;
	acme_enabled: boolean;
	acme_server_name?: string;
};

export type AsideFormData = {
	formTitle: string;
	user?: {
		id: string;
		email: string;
	};
};

export type ACMEServerEntry = {
	id: number;
	name: string;
	directory_url: string;
	email: string;
	dns_provider: string;
	active: boolean;
	env_var_keys: string[];
};

export type ClusterRole = "voter" | "standby" | "spare";

/** Derived by the server from the member's last heartbeat. */
export type ClusterMemberStatus = "ONLINE" | "OFFLINE";

export type ClusterMemberEntry = {
	/** The dqlite node ID. It is a string because it does not fit an int64. */
	id: string;
	name: string;
	address: string;
	role: ClusterRole;
	leader: boolean;
	/** The member's own last report. Only as fresh as `last_seen`. */
	sealed: boolean;
	/** Unix seconds of the member's last heartbeat, or 0 if it never sent one. */
	last_seen: number;
	status: ClusterMemberStatus;
	/** Human-readable detail for `status`, e.g. why a member is offline. */
	message: string;
};

export type ClusterStatusEntry = {
	enabled: boolean;
	node_id: string;
	address: string;
	/** Empty while no leader is elected: an election or a quorum loss. */
	leader_id: string;
	voters: number;
	members: ClusterMemberEntry[];
};

export type ClusterJoinTokenEntry = {
	/** Returned exactly once, when the token is created. Only its hash is stored. */
	token: string;
	/** Advertise address the token is bound to. */
	identity: string;
	/** Unix seconds. */
	expires_at: number;
};
