import {
	ActionButton,
	Button,
	CodeSnippet,
	Input,
	Modal,
	Notification,
	Select,
} from "@canonical/react-components";
import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { createClusterJoinToken } from "@/utils/queries";
import { type ClusterJoinTokenEntry, getErrorMessage } from "@/utils/types";

type AddNodeModalProps = {
	close: () => void;
	/**
	 * The admin API address of this node, which is what the joining node has to
	 * contact. The browser is talking to it right now, so its own location is
	 * the one address known to be reachable.
	 */
	apiAddress: string;
};

const ttlOptions = [
	{ label: "15 minutes", value: "900" },
	{ label: "1 hour", value: "3600" },
	{ label: "6 hours", value: "21600" },
	{ label: "24 hours", value: "86400" },
];

export function AddNodeModal({ close, apiAddress }: AddNodeModalProps) {
	const [ttlSeconds, setTTLSeconds] = useState<string>("3600");
	const [identity, setIdentity] = useState<string>("");
	const [token, setToken] = useState<ClusterJoinTokenEntry | null>(null);

	const mutation = useMutation({
		mutationFn: createClusterJoinToken,
		onSuccess: (created) => setToken(created),
	});

	if (token) {
		return (
			<Modal
				title="Add a node"
				close={close}
				buttonRow={
					<Button appearance="positive" onClick={close}>
						Done
					</Button>
				}
			>
				<Notification severity="caution" title="Shown once">
					This token is not stored and cannot be shown again. Copy it now. It is
					bound to {token.identity} and is only for join preflight, not cluster
					mTLS. Provision that node's cluster certificates before running join.
				</Notification>
				<p>Run this on the new node, before starting Notary on it:</p>
				<CodeSnippet
					blocks={[
						{
							code: `notary cluster join --config /path/to/notary.yaml --address ${apiAddress} --ca-cert /path/to/api.crt -- ${token.token}`,
							wrapLines: true,
						},
					]}
				/>
				<p className="u-text--muted">
					Replace the paths with the new node's configuration file, and with a
					copy of this node's API certificate. <code>cluster.address</code> in
					that configuration must be {token.identity}. <code>--ca-cert</code>{" "}
					pins this node's API certificate so the join cannot be redirected.
				</p>
				<p className="u-text--muted">
					Expires {new Date(token.expires_at * 1000).toLocaleString()}. The new
					member takes its Raft role from the cluster automatically.
				</p>
			</Modal>
		);
	}

	return (
		<Modal
			title="Add a node"
			close={close}
			buttonRow={
				<>
					<Button onClick={close}>Cancel</Button>
					<ActionButton
						appearance="positive"
						loading={mutation.isPending}
						disabled={identity.trim() === ""}
						onClick={() =>
							mutation.mutate({
								identity: identity.trim(),
								ttl_seconds: Number(ttlSeconds),
							})
						}
					>
						Generate Token
					</ActionButton>
				</>
			}
		>
			<Input
				type="text"
				label="Joining node advertise address"
				placeholder="10.0.0.4:9000"
				value={identity}
				onChange={(event) => setIdentity(event.target.value)}
				help="Must match cluster.address on the new node. The token will only admit that identity."
			/>
			<Select
				label="Valid for"
				value={ttlSeconds}
				onChange={(event) => setTTLSeconds(event.target.value)}
				options={ttlOptions}
				help="The token is single use. A short window is safer."
			/>
			{mutation.isError && (
				<Notification severity="negative" title="Error">
					{getErrorMessage(mutation.error)}
				</Notification>
			)}
		</Modal>
	);
}
