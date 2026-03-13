"use client";

import { useQuery } from "@tanstack/react-query";
import { getConfig } from "@/queries";
import { ConfigEntry } from "@/types";
import Loading from "@/components/loading";
import Error from "@/components/error";
import { retryUnlessUnauthorized } from "@/utils";
import { AppMain, MainTable, Panel } from "@canonical/react-components";
import NotaryAppNavigationBars from "@/components/NotaryAppNavigationBars";
import { Application } from "@canonical/react-components";
import NotaryAppStatus from "@/components/NotaryAppStatus";

function formatLabel(key: string): string {
  return key
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function ConfigTable({ config }: { config: ConfigEntry }) {
  const rows = [
    { key: "port", value: config.port.toString() },
    {
      key: "pebble_notifications",
      value: config.pebble_notifications ? "Enabled" : "Disabled",
    },
    { key: "logging_level", value: config.logging_level },
    { key: "logging_output", value: config.logging_output },
    { key: "encryption_backend_type", value: config.encryption_backend_type },
  ];

  return (
    <Panel stickyHeader title="Server Info" className="u-fixed-width">
      <MainTable
        headers={[
          { content: "Setting", sortKey: "setting" },
          { content: "Value", sortKey: "value" },
        ]}
        rows={rows.map((row) => ({
          columns: [{ content: formatLabel(row.key) }, { content: row.value }],
          sortData: {
            setting: formatLabel(row.key),
            value: row.value,
          },
        }))}
        sortable
      />
    </Panel>
  );
}

export default function Configuration() {
  const query = useQuery<ConfigEntry, Error>({
    queryKey: ["config"],
    queryFn: getConfig,
    retry: retryUnlessUnauthorized,
  });
  if (query.status == "pending") {
    return <Loading />;
  }
  if (query.status == "error") {
    return <Error msg={query.error.message} />;
  }
  return (
    <Application>
      <NotaryAppNavigationBars />
      <AppMain>
        <ConfigTable config={query.data} />
      </AppMain>
      <NotaryAppStatus />
    </Application>
  );
}
