import { getSelfAccount, getStatus } from "@/utils/queries";
import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";

import { useLocation, useNavigate } from "@tanstack/react-router";
// This hook manages some redirects based on the user's login status, notary's initialization status and the current page.
// If Notary isn't initialized, it will redirect the user to the initialization page.
// If the user isn't logged in, it will redirect the user to the login page.
// If the user is logged in and tries to go to the login or initialize page, it will redirect the user to the home page.
export function useLoginRedirect() {
  const location = useLocation();
  const navigate = useNavigate();

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
      navigate({
        to: "/initialize",
        replace: true,
      });
      return;
    }
    if (notaryUserNotLoggedIn) {
      navigate({
        to: "/login",
        replace: true,
      });
      return;
    }
    if (notaryUserLoggedIn && location.pathname == "/login") {
      navigate({
        to: "/",
        replace: true,
      });
      return;
    }
    if (notaryUserLoggedIn && location.pathname == "/initialize") {
      navigate({
        to: "/",
        replace: true,
      });
      return;
    }
  }, [
    statusQ.data,
    statusQ.isLoading,
    userQ.isLoading,
    userQ.data,
    userQ.isError,
    navigate,
    location.pathname,
  ]);
}
