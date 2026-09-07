import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import type { ClusterMemberEntry } from "@/utils/types";
import { ClusterTable } from "./table";

const members: ClusterMemberEntry[] = [
	{
		name: "node1",
		id: 1,
		address: "10.0.0.1:9000",
		api_address: "10.0.0.1:8000",
		role: "voter",
		leader: true,
	},
	{
		name: "node2",
		id: 2,
		address: "10.0.0.2:9000",
		api_address: "10.0.0.2:8000",
		role: "spare",
		leader: false,
	},
];

test("renders cluster members like lxc cluster list", () => {
	render(
		<QueryClientProvider client={new QueryClient()}>
			<ClusterTable members={members} setAsideOpen={() => {}} />
		</QueryClientProvider>,
	);
	expect(screen.getByText("node1")).toBeTruthy();
	expect(screen.getByText("10.0.0.1:9000")).toBeTruthy();
	expect(screen.getByText("10.0.0.1:8000")).toBeTruthy();
	expect(screen.getByText("voter")).toBeTruthy();
	expect(screen.getByText("Yes")).toBeTruthy();
	expect(screen.getByText("node2")).toBeTruthy();
	expect(screen.getByText("spare")).toBeTruthy();
	expect(screen.getByText("No")).toBeTruthy();
});
