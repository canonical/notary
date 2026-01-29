import { getSelfAccount, getStatus } from "@/queries";
import { useQuery } from "@tanstack/react-query";
import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";

// This hook manages some redirects based on the user's login status, notary's initialization status and the current page.
// If Notary isn't initialized, it will redirect the user to the initialization page.
// If the user isn't logged in, it will redirect the user to the login page.
// If the user is logged in and tries to go to the login or initialize page, it will redirect the user to the home page.
export function useLoginRedirect() {
  const router = useRouter();
  const path = usePathname();

  const statusQ = useQuery({
    queryKey: ["status"],
    queryFn: getStatus,
    staleTime: Infinity,
    retry: false,
  });

  const userQ = useQuery({
    queryKey: ["user"],
    queryFn: getSelfAccount,
    staleTime: 5 * 60 * 1000,
    retry: false,
  });

  useEffect(() => {
    const notaryStatusIsLoading = statusQ.isLoading;
    const notaryUserDataIsLoading = userQ.isLoading;
    const notaryIsNotInitialized = statusQ.data && !statusQ.data.initialized;
    const notaryUserNotLoggedIn = !statusQ.isLoading && userQ.isError;
    const notaryUserLoggedIn = !statusQ.isLoading && userQ.data;

    if (notaryStatusIsLoading || notaryUserDataIsLoading) return;
    if (notaryIsNotInitialized) {
      router.push("/initialize");
      return;
    }
    if (notaryUserNotLoggedIn) {
      router.push("/login");
      return;
    }
    if (notaryUserLoggedIn && path == "/login") {
      router.push("/");
      return;
    }
    if (notaryUserLoggedIn && path == "/initialize") {
      router.push("/");
      return;
    }
  }, [
    statusQ.data,
    statusQ.isLoading,
    userQ.isLoading,
    userQ.data,
    userQ.isError,
    router,
    path,
  ]);
}
