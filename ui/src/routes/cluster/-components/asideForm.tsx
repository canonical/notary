import {
	Button,
	Form,
	Input,
	Notification,
	Panel,
	useToastNotification,
} from "@canonical/react-components";
import { useMutation } from "@tanstack/react-query";
import {
	type ChangeEvent,
	type Dispatch,
	type SetStateAction,
	useState,
} from "react";
import { addClusterMember } from "@/utils/queries";
import { type ClusterJoinToken, getErrorMessage } from "@/utils/types";

type AsideProps = {
	setAsideOpen: Dispatch<SetStateAction<boolean>>;
};

const memberNamePattern = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,62})$/;

export default function ClusterPageAsidePanel({ setAsideOpen }: AsideProps) {
	const toastNotify = useToastNotification();
	const [serverName, setServerName] = useState("");
	const [errorText, setErrorText] = useState("");
	const [token, setToken] = useState<ClusterJoinToken | null>(null);

	const mutation = useMutation({
		mutationFn: addClusterMember,
		onSuccess: (data) => {
			setToken(data);
			setErrorText("");
			toastNotify.success(
				"Copy the token and start the new node with it. The token is valid for three hours.",
				undefined,
				"Join token created",
			);
		},
		onError: (e: Error) => {
			setErrorText(getErrorMessage(e));
			toastNotify.failure(
				"Could not create a join token",
				e,
				"Failed to add the member.",
			);
		},
	});

	const handleCopy = async () => {
		if (!token) {
			return;
		}
		try {
			await navigator.clipboard.writeText(token.join_token);
			toastNotify.success("Join token copied.", undefined, "Copied");
		} catch (e) {
			toastNotify.failure("Copy failed", e as Error, "Copy the token by hand.");
		}
	};

	const handleClose = () => {
		setServerName("");
		setErrorText("");
		setToken(null);
		setAsideOpen(false);
	};

	return (
		<Panel
			title={token ? "Join token" : "Add a member"}
			controls={
				<Button onClick={handleClose} hasIcon>
					<i className="p-icon--close" />
				</Button>
			}
		>
			{token ? (
				<>
					<p>
						Start the new node with an empty <code>db_path</code> and this
						token. Until it is redeemed or expires, anyone who has it can
						collect the cluster private key.
					</p>
					<Input
						type="text"
						id="join-token"
						label="Join token"
						readOnly
						value={token.join_token}
					/>
					<p className="p-text--small">
						<code>
							notary start --config /etc/notary/config/config.yaml --join '
							{token.join_token}'
						</code>
					</p>
					<Button appearance="positive" onClick={() => void handleCopy()}>
						Copy token
					</Button>
				</>
			) : (
				<Form
					onSubmit={(e) => {
						e.preventDefault();
						if (!memberNamePattern.test(serverName)) {
							setErrorText(
								"Use a hostname-like name: letters, digits, dots, or hyphens.",
							);
							return;
						}
						mutation.mutate({ server_name: serverName });
					}}
				>
					{errorText !== "" && (
						<Notification severity="negative" title="Error">
							{errorText}
						</Notification>
					)}
					<Input
						id="server-name"
						type="text"
						label="Member name"
						help="Same name as cluster.name on the joiner."
						value={serverName}
						onChange={(e: ChangeEvent<HTMLInputElement>) =>
							setServerName(e.target.value)
						}
						required
					/>
					<Button
						appearance="positive"
						type="submit"
						disabled={mutation.isPending || serverName === ""}
					>
						Create join token
					</Button>
				</Form>
			)}
		</Panel>
	);
}
