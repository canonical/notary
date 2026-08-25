import {
	Button,
	ContextualMenu,
	MainTable,
	Panel,
} from "@canonical/react-components";
import { useState } from "react";
import {
	NotaryConfirmationModal,
	type NotaryConfirmationModalData,
} from "@/components/NotaryConfirmationModal";
import { deleteClusterMember, promoteClusterMember } from "@/utils/queries";
import type { ClusterMemberEntry, ClusterStatusEntry } from "@/utils/types";

type ClusterTableProps = {
	status: ClusterStatusEntry;
	/** The dqlite node ID of the node serving this UI. */
	localNodeID: string;
	onAddNode: () => void;
};

const roleLabels: Record<string, string> = {
	voter: "Voter",
	standby: "Standby",
	spare: "Spare",
};

const onlineColour = "rgba(14, 132, 32, 1)";
const offlineColour = "rgba(199, 22, 44, 1)";

// Every member reports its own seal state through the replicated database, but
// that report is only as fresh as its last heartbeat: a member that has stopped
// sending them has no current seal state to show.
function sealStateLabel(member: ClusterMemberEntry) {
	if (member.status !== "ONLINE") {
		return (
			<span
				className="u-text--muted"
				title="This member has not reported recently, so its seal state is out of date."
			>
				Unknown
			</span>
		);
	}
	return member.sealed ? (
		<span style={{ color: offlineColour }}>● Sealed</span>
	) : (
		<span style={{ color: onlineColour }}>● Unsealed</span>
	);
}

// The message carries the detail behind the state, including when an offline
// member was last seen. It is rendered as text, not only as a tooltip, so it is
// reachable without a pointer.
function memberStateLabel(member: ClusterMemberEntry) {
	const online = member.status === "ONLINE";
	return (
		<>
			<span style={{ color: online ? onlineColour : offlineColour }}>
				● {member.status}
			</span>
			<br />
			<small className="u-text--muted">{member.message}</small>
		</>
	);
}

function raftStateLabel(member: ClusterMemberEntry, leaderID: string) {
	if (member.leader) {
		return "Leader";
	}
	// An empty leader ID means no leader is elected: an in-flight election, or a
	// lost quorum. Calling every member a follower then would be a lie.
	return leaderID === "" ? "No leader" : "Follower";
}

export function ClusterTable({
	status,
	localNodeID,
	onAddNode,
}: ClusterTableProps) {
	const [confirmationModalData, setConfirmationModalData] =
		// biome-ignore lint/suspicious/noExplicitAny: generic modal accepts any data type
		useState<NotaryConfirmationModalData<any> | null>(null);

	const memberLabel = (member: ClusterMemberEntry) =>
		member.name !== "" ? member.name : member.address;

	const handlePromote = (member: ClusterMemberEntry) => {
		setConfirmationModalData({
			queryFn: promoteClusterMember,
			queryParams: { id: member.id },
			queryKey: "cluster_status",
			closeFn: () => setConfirmationModalData(null),
			buttonConfirmText: "Promote",
			warningText: `"${memberLabel(member)}" will become a voter and start taking part in Raft quorum decisions.`,
			successTitle: "Member promoted",
			successMessage: `"${memberLabel(member)}" is now a voter.`,
			failureMessage: "Failed to promote the cluster member.",
		});
	};

	const handleRemove = (member: ClusterMemberEntry, force: boolean) => {
		setConfirmationModalData({
			queryFn: deleteClusterMember,
			queryParams: { id: member.id, force: force },
			queryKey: "cluster_status",
			closeFn: () => setConfirmationModalData(null),
			buttonConfirmText: force ? "Force Remove" : "Remove",
			warningText: force
				? `"${memberLabel(member)}" will be removed without handing over its Raft responsibilities first. Only do this for a member that is already gone.`
				: `"${memberLabel(member)}" will hand over its Raft responsibilities and leave the cluster. Rejoining requires a new join token.`,
			successTitle: "Member removed",
			successMessage: `"${memberLabel(member)}" was removed from the cluster.`,
			failureMessage: "Failed to remove the cluster member.",
		});
	};

	const rows = status.members.map((member) => ({
		sortData: {
			name: memberLabel(member),
			address: member.address,
			role: member.role,
		},
		columns: [
			{
				content: (
					<>
						{memberLabel(member)}
						{member.id === localNodeID && (
							<span className="u-text--muted"> (this node)</span>
						)}
						<br />
						{/* The ID is what promote and remove take, and it is all there is
						    to go on for a member whose name was never recorded. */}
						<small className="u-text--muted">{member.id}</small>
					</>
				),
			},
			{ content: member.address },
			{ content: roleLabels[member.role] ?? member.role },
			{ content: raftStateLabel(member, status.leader_id) },
			{ content: memberStateLabel(member) },
			{
				content: sealStateLabel(member),
			},
			{
				content: (
					<ContextualMenu hasToggleIcon position="right">
						<span className="p-contextual-menu__group">
							<Button
								className="p-contextual-menu__link"
								disabled={member.role === "voter"}
								onClick={() => handlePromote(member)}
							>
								Promote to Voter
							</Button>
							<Button
								className="p-contextual-menu__link"
								disabled={member.id === localNodeID}
								onClick={() => handleRemove(member, false)}
							>
								Remove
							</Button>
							<Button
								className="p-contextual-menu__link"
								disabled={
									member.id === localNodeID || member.status === "ONLINE"
								}
								onClick={() => handleRemove(member, true)}
							>
								Force Remove
							</Button>
						</span>
					</ContextualMenu>
				),
				className: "u-align--right",
				hasOverflow: true,
			},
		],
	}));

	return (
		<Panel
			stickyHeader
			title="Cluster"
			className="u-fixed-width"
			controls={
				<Button appearance="positive" onClick={onAddNode}>
					Add Node
				</Button>
			}
		>
			<p className="u-text--muted">
				{status.members.length} member
				{status.members.length === 1 ? "" : "s"}, {status.voters} voter
				{status.voters === 1 ? "" : "s"}.{" "}
				{status.leader_id === ""
					? "No leader is currently elected."
					: "A leader is elected."}
			</p>
			<MainTable
				headers={[
					{ content: "Name" },
					{ content: "Address" },
					{ content: "Role" },
					{ content: "Raft State" },
					{ content: "State" },
					{ content: "Seal State" },
					{
						content: "Actions",
						className: "u-align--right has-overflow",
					},
				]}
				rows={rows}
			/>
			{confirmationModalData && (
				<NotaryConfirmationModal {...confirmationModalData} />
			)}
		</Panel>
	);
}
