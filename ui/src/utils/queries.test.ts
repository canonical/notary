import { afterEach, expect, test, vi } from "vitest";
import { getStatus } from "./queries";

afterEach(() => {
	vi.unstubAllGlobals();
});

test("returns local diagnostics from a degraded status response", async () => {
	const status = {
		initialized: true,
		version: "dev",
		oidc_enabled: false,
		sealed: false,
		node_id: "7",
		role: "voter",
		raft_state: "no-leader",
	};
	vi.stubGlobal(
		"fetch",
		vi.fn().mockResolvedValue(
			new Response(
				JSON.stringify({ message: "storage unavailable", data: status }),
				{
					status: 503,
					headers: { "Content-Type": "application/json" },
				},
			),
		),
	);

	await expect(getStatus()).resolves.toEqual({
		...status,
		storage_available: false,
	});
});

test("rejects a degraded status response without diagnostics", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn().mockResolvedValue(
			new Response(JSON.stringify({ message: "storage unavailable" }), {
				status: 503,
				headers: { "Content-Type": "application/json" },
			}),
		),
	);

	await expect(getStatus()).rejects.toThrow("storage unavailable");
});
