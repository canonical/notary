import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
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

// The row actions live behind a contextual menu, so it has to be opened before
// its buttons exist in the DOM. Each case renders a single member, which keeps
// the assertions independent of how the table happens to sort its rows.
function openMenuFor(member: ClusterStatusEntry["members"][number]) {
	cleanup();
	renderTable({ members: [member] });
	fireEvent.click(screen.getByLabelText("Toggle menu"));
}

// Asserting on the confirmation prompt rather than the disabled attribute: what
// matters is that a blocked action cannot be started, not how it is styled.
function clickAction(name: string) {
	fireEvent.click(screen.getByRole("button", { name }));
}

const local = status.members[0];
const remote = status.members[1];

// Removing the node serving this page would take away the API the request is
// travelling over, so the local member is never removable from its own UI.
test("blocks removal of the local node but allows it for the others", () => {
	openMenuFor(local);
	clickAction("Remove");
	expect(screen.queryByText(/will hand over its Raft/)).toBeNull();

	openMenuFor(remote);
	clickAction("Remove");
	expect(screen.getByText(/will hand over its Raft/)).toBeDefined();
});

// Force removal skips the Raft handover, which is only safe for a member that
// is already gone.
test("offers force removal only for an offline member", () => {
	openMenuFor(remote);
	clickAction("Force Remove");
	expect(screen.queryByText(/removed without handing over/)).toBeNull();

	openMenuFor({
		...remote,
		status: "OFFLINE",
		message: "No heartbeat since 2026-08-24T11:05:25Z",
	});
	clickAction("Force Remove");
	expect(screen.getByText(/removed without handing over/)).toBeDefined();
});

test("does not offer to promote a member that is already a voter", () => {
	openMenuFor(local);
	clickAction("Promote to Voter");
	expect(screen.queryByText(/will become a voter/)).toBeNull();

	openMenuFor(remote);
	clickAction("Promote to Voter");
	expect(screen.getByText(/will become a voter/)).toBeDefined();
});
