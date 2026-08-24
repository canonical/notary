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
			sealed: false,
			last_seen: 1700000000,
			status: "ONLINE",
			message: "Fully operational",
		},
		{
			id: "2",
			name: "",
			address: "10.0.0.2:7000",
			role: "standby",
			leader: false,
			sealed: false,
			last_seen: 1700000000,
			status: "ONLINE",
			message: "Fully operational",
		},
	],
};

function renderTable(overrides: Partial<ClusterStatusEntry> = {}) {
	render(
		<QueryClientProvider client={new QueryClient()}>
			<ClusterTable
				status={{ ...status, ...overrides }}
				localNodeID="1"
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

test("reports each member's own seal state, not just the local node's", () => {
	renderTable({
		members: [
			{ ...status.members[0], sealed: false },
			{ ...status.members[1], sealed: true },
		],
	});

	expect(screen.getByText("● Unsealed")).toBeDefined();
	expect(screen.getByText("● Sealed")).toBeDefined();
	expect(screen.queryByText("Unknown")).toBeNull();
});

// An offline member's last report is stale, so it is not presented as current.
test("withholds seal state for a member that is offline", () => {
	renderTable({
		members: [
			status.members[0],
			{
				...status.members[1],
				sealed: false,
				status: "OFFLINE",
				message: "No heartbeat since 2026-08-24T11:05:25Z",
			},
		],
	});

	expect(screen.getByText("● ONLINE")).toBeDefined();
	expect(screen.getByText("● OFFLINE")).toBeDefined();
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
