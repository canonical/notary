import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";
import type { ClusterStatusEntry } from "@/utils/types";
import { ClusterTable } from "./table";

// Testing Library only cleans up automatically when a global afterEach is
// registered, and this project runs vitest without globals.
afterEach(cleanup);

const status: ClusterStatusEntry = {
	enabled: true,
	node_id: "1",
	address: "10.0.0.1:7000",
	leader_id: "1",
	voters: 1,
	members: [
		{
			id: "1",
			name: "node-a",
			address: "10.0.0.1:7000",
			role: "voter",
			leader: true,
		},
		{
			id: "2",
			name: "",
			address: "10.0.0.2:7000",
			role: "standby",
			leader: false,
		},
	],
};

function renderTable(overrides: Partial<ClusterStatusEntry> = {}) {
	render(
		<QueryClientProvider client={new QueryClient()}>
			<ClusterTable
				status={{ ...status, ...overrides }}
				localNodeID="1"
				localNodeSealed={false}
				onAddNode={() => {}}
			/>
		</QueryClientProvider>,
	);
}

test("renders every member with its role", () => {
	renderTable();

	expect(screen.getByText("node-a")).toBeDefined();
	expect(screen.getByText("Voter")).toBeDefined();
	expect(screen.getByText("Standby")).toBeDefined();
});

test("falls back to the address for a member with no recorded name", () => {
	renderTable();

	expect(screen.getAllByText("10.0.0.2:7000").length).toBe(2);
});

test("reports seal state only for the node serving the page", () => {
	renderTable();

	expect(screen.getByText("● Unsealed")).toBeDefined();
	expect(screen.getByText("Unknown")).toBeDefined();
});

test("does not call any member a follower while no leader is elected", () => {
	renderTable({
		leader_id: "",
		members: status.members.map((member) => ({ ...member, leader: false })),
	});

	expect(screen.queryByText("Follower")).toBeNull();
	expect(screen.getAllByText("No leader")).toHaveLength(2);
});
