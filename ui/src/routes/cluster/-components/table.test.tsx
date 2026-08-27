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
		<ClusterTable
			status={{ ...status, ...overrides }}
			localNodeID="1"
			onAddNode={() => {}}
		/>,
	);
}

test("renders every member with its role", () => {
	renderTable();

	expect(screen.getByText("node-a")).toBeDefined();
	expect(screen.getByText("database-leader")).toBeDefined();
	expect(screen.getByText("database-standby")).toBeDefined();
});

test("falls back to the address for a member with no recorded name", () => {
	renderTable();

	expect(screen.getAllByText("10.0.0.2:7000").length).toBe(2);
});

test("shows seal detail in the message column", () => {
	renderTable({
		members: [
			{ ...status.members[0], sealed: false, message: "Fully operational" },
			{
				...status.members[1],
				sealed: true,
				message: "Sealed, waiting to unwrap its encryption key",
			},
		],
	});

	expect(screen.getByText("Fully operational")).toBeDefined();
	expect(
		screen.getByText("Sealed, waiting to unwrap its encryption key"),
	).toBeDefined();
});

test("shows why a member is offline as text, not only on hover", () => {
	renderTable({
		members: [
			{
				...status.members[1],
				status: "OFFLINE",
				message: "No heartbeat since 2026-08-24T11:05:25Z",
			},
		],
	});

	expect(screen.getByText("● OFFLINE")).toBeDefined();
	expect(
		screen.getByText("No heartbeat since 2026-08-24T11:05:25Z"),
	).toBeDefined();
});

test("shows the node ID of a member that has no name", () => {
	renderTable({
		members: [{ ...status.members[1], id: "15559759156573841049", name: "" }],
	});

	expect(screen.getByText("15559759156573841049")).toBeDefined();
});

test("does not offer membership actions", () => {
	renderTable();
	expect(screen.queryByLabelText("Toggle menu")).toBeNull();
	expect(screen.queryByRole("button", { name: "Promote to Voter" })).toBeNull();
	expect(screen.queryByRole("button", { name: "Remove" })).toBeNull();
	expect(screen.queryByRole("button", { name: "Force Remove" })).toBeNull();
});
