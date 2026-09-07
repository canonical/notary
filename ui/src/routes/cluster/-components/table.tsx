import {
	Button,
	ContextualMenu,
	MainTable,
	Panel,
} from "@canonical/react-components";
import { type Dispatch, type SetStateAction, useState } from "react";
import {
	NotaryConfirmationModal,
	type NotaryConfirmationModalData,
} from "@/components/NotaryConfirmationModal";
import { removeClusterMember } from "@/utils/queries";
import type { ClusterMemberEntry } from "@/utils/types";

type TableProps = {
	members: ClusterMemberEntry[];
	setAsideOpen: Dispatch<SetStateAction<boolean>>;
};

export function ClusterTable({ members, setAsideOpen }: TableProps) {
	const [confirmationModalData, setConfirmationModalData] =
		useState<NotaryConfirmationModalData<{ name: string }> | null>(null);
	const lastMember = members.length <= 1;

	return (
		<Panel
			stickyHeader
			title="Cluster"
			className="u-fixed-width"
			controls={
				<Button
					appearance="positive"
					onClick={() => {
						setAsideOpen(true);
					}}
				>
					Add member
				</Button>
			}
		>
			<p>
				Members share one dqlite database. Add a member to mint a join token,
				then start the new node with an empty data directory and{" "}
				<code>notary start --join</code>.
			</p>
			<MainTable
				headers={[
					{ content: "Name" },
					{ content: "Address" },
					{ content: "API address" },
					{ content: "Role" },
					{ content: "Leader" },
					{
						content: "Actions",
						className: "u-align--right has-overflow",
					},
				]}
				rows={members.map((member) => {
					const label = member.name || member.address;
					return {
						columns: [
							{ content: member.name || "—" },
							{ content: member.address },
							{ content: member.api_address || "—" },
							{ content: member.role },
							{ content: member.leader ? "Yes" : "No" },
							{
								content: (
									<ContextualMenu
										links={[
											{
												children: "Remove",
												disabled: lastMember,
												onClick: () =>
													setConfirmationModalData({
														queryFn: async (params) => {
															await removeClusterMember(params);
															return params;
														},
														queryParams: { name: label },
														closeFn: () => setConfirmationModalData(null),
														queryKey: "cluster",
														warningText: `Remove member "${label}" from the cluster? Stop Notary on that machine afterwards. This cannot be undone.`,
														buttonConfirmText: "Remove",
														successTitle: "Member removed",
														successMessage: `Member ${label} was removed.`,
														failureMessage: "Failed to remove the member.",
													}),
											},
										]}
										hasToggleIcon
										position="right"
										style={{ height: "40px" }}
									/>
								),
								className: "u-align--right",
								hasOverflow: true,
							},
						],
					};
				})}
			/>
			{confirmationModalData && (
				<NotaryConfirmationModal {...confirmationModalData} />
			)}
		</Panel>
	);
}
