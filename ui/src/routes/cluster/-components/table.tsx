import { Button, MainTable, Panel } from "@canonical/react-components";
import type { ClusterMemberEntry, ClusterStatusEntry } from "@/utils/types";

type ClusterTableProps = {
	status: ClusterStatusEntry;
	/** The dqlite node ID of the node serving this UI. */
	localNodeID: string;
	onAddNode: () => void;
};

const onlineColour = "rgba(14, 132, 32, 1)";
const offlineColour = "rgba(199, 22, 44, 1)";

// Matches `lxc cluster list`: the leader is a role, not a separate column.
function memberRoles(member: ClusterMemberEntry) {
	if (member.leader) {
		return "database-leader";
	}
	switch (member.role) {
		case "voter":
			return "database-voter";
		case "standby":
			return "database-standby";
		default:
			return member.role;
	}
}

function memberStateLabel(member: ClusterMemberEntry) {
	const online = member.status === "ONLINE";
	return (
		<span style={{ color: online ? onlineColour : offlineColour }}>
			● {member.status}
		</span>
	);
}

export function ClusterTable({
	status,
	localNodeID,
	onAddNode,
}: ClusterTableProps) {
	const memberLabel = (member: ClusterMemberEntry) =>
		member.name !== "" ? member.name : member.address;

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
						<small className="u-text--muted">{member.id}</small>
					</>
				),
			},
			{ content: member.address },
			{ content: memberRoles(member) },
			{ content: memberStateLabel(member) },
			{ content: member.message },
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
					{ content: "URL" },
					{ content: "Roles" },
					{ content: "State" },
					{ content: "Message" },
				]}
				rows={rows}
			/>
		</Panel>
	);
}
