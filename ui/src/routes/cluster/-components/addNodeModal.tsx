import {
	ActionButton,
	Button,
	CodeSnippet,
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
					This token is not stored and cannot be shown again. Copy it now. It
					grants membership of the cluster, so treat it as a credential and let
					it expire unused if you do not need it.
				</Notification>
				<p>Run this on the new node, before starting Notary on it:</p>
				<CodeSnippet
					blocks={[
						{
							code: `notary cluster join ${token.token} --config <config file> --address ${apiAddress} --ca-cert <this node's API certificate>`,
							wrapLines: true,
						},
					]}
				/>
				<p className="u-text--muted">
					Copy this node's API certificate to the new node and pass it as
					<code>--ca-cert</code>. Without it the join is verified against the
					system trust store, which will reject a self-signed certificate.
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
						onClick={() =>
							mutation.mutate({
								ttl_seconds: Number(ttlSeconds),
							})
						}
					>
						Generate Token
					</ActionButton>
				</>
			}
		>
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
