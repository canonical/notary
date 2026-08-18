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
	/** Whether the node serving this UI has unwrapped its encryption key. */
	localNodeSealed: boolean;
	onAddNode: () => void;
};

const roleLabels: Record<string, string> = {
	voter: "Voter",
	standby: "Standby",
	spare: "Spare",
};

// Seal state is per node and only observable on the node being asked. This UI is
// served by exactly one member, so that is the only member whose seal state can
// be reported here. The rest are left explicitly unknown rather than assumed.
function sealStateLabel(
	member: ClusterMemberEntry,
	localNodeID: string,
	localNodeSealed: boolean,
) {
	if (member.id !== localNodeID) {
		return (
			<span
				className="u-text--muted"
				title="Seal state is only reported by the node serving this page. Open this page on the member, or run `notary cluster status` against it, to see its seal state."
			>
				Unknown
			</span>
		);
	}
	return localNodeSealed ? (
		<span style={{ color: "rgba(199, 22, 44, 1)" }}>● Sealed</span>
	) : (
		<span style={{ color: "rgba(14, 132, 32, 1)" }}>● Unsealed</span>
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
	localNodeSealed,
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
					</>
				),
			},
			{ content: member.address },
			{ content: roleLabels[member.role] ?? member.role },
			{ content: raftStateLabel(member, status.leader_id) },
			{
				content: sealStateLabel(member, localNodeID, localNodeSealed),
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
								onClick={() => handleRemove(member, false)}
							>
								Remove
							</Button>
							<Button
								className="p-contextual-menu__link"
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
