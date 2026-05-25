import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getSelfAccount, logout } from "@/utils/queries";

export function useAuth() {
	const queryClient = useQueryClient();
	const user = useQuery({
		queryKey: ["user"],
		queryFn: getSelfAccount,
		staleTime: 5 * 60 * 1000,
		retry: false,
	});

	const logoutMutation = useMutation({
		mutationFn: async () => {
			await logout();
			await queryClient.invalidateQueries({ queryKey: ["user"] });
		},
	});

	return {
		user: user.data ? user.data : null,
		logout: () => logoutMutation.mutate(),
	};
}
