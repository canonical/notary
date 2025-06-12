"use client";

import { useQuery } from "@tanstack/react-query";
import { ListUsers } from "@/queries";
import { AsideFormData, UserEntry } from "@/types";
import { useCookies } from "react-cookie";
import { useRouter } from "next/navigation";
import { UsersTable } from "./table";
import Loading from "@/components/loading";
import Error from "@/components/error";
import { retryUnlessUnauthorized } from "@/utils";
import { AppMain } from "@canonical/react-components";
import { AppAside } from "@canonical/react-components";
import NotaryAppNavigationBars from "@/components/NotaryAppNavigationBars";
import { Application } from "@canonical/react-components";
import NotaryAppStatus from "@/components/NotaryAppStatus";
import { useState } from "react";
import UsersPageAsidePanel from "./asideForm";

export default function Users() {
  const router = useRouter();
  const [asideOpen, setAsideOpen] = useState<boolean>(false);
  const [formData, setFormData] = useState<AsideFormData>({
    formTitle: "Add a New User",
  });
  const [cookies, , removeCookie] = useCookies(["user_token"]);
  if (!cookies.user_token) {
    router.push("/login");
  }
  const query = useQuery<UserEntry[], Error>({
    queryKey: ["users", cookies.user_token],
    queryFn: () =>
      // eslint-disable-next-line
      ListUsers({ authToken: cookies.user_token ? cookies.user_token : "" }),
    retry: retryUnlessUnauthorized,
  });
  if (query.status == "pending") {
    return <Loading />;
  }
  if (query.status == "error") {
    if (query.error.message.includes("401")) {
      removeCookie("user_token");
    }
    if (query.error.message.includes("403")) {
      return (
        <Error msg="403 Forbidden: You do not have access to this page." />
      );
    }
    return <Error msg={query.error.message} />;
  }
  const users = Array.from(query.data ? query.data : []);
  return (
    <Application>
      <NotaryAppNavigationBars />
      <AppAside collapsed={!asideOpen}>
        <UsersPageAsidePanel setAsideOpen={setAsideOpen} formData={formData} />
      </AppAside>
      <AppMain>
        <UsersTable
          users={users}
          setAsideOpen={setAsideOpen}
          setFormData={setFormData}
        />
      </AppMain>
      <NotaryAppStatus />
    </Application>
  );
}
