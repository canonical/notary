import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { getConfig } from "@/utils/queries";
import { type ConfigEntry, getErrorMessage } from "@/utils/types";
import Loading from "@/components/loading";
import Error from "@/components/error";
import { retryUnlessUnauthorized } from "@/utils/helpers";
import {
  AppMain,
  MainTable,
  Panel,
  ToastNotificationProvider,
} from "@canonical/react-components";
import NotaryAppNavigationBars from "@/components/NotaryAppNavigationBars";
import { Application } from "@canonical/react-components";
import NotaryAppStatus from "@/components/NotaryAppStatus";

export const Route = createFileRoute("/configuration")({
  component: ConfigurationPageComponent,
});

function ConfigurationPageComponent() {
  const query = useQuery<ConfigEntry, Error>({
    queryKey: ["config"],
    queryFn: getConfig,
    retry: retryUnlessUnauthorized,
  });
  if (query.status == "pending") {
    return <Loading />;
  }
  if (query.status == "error") {
    return <Error msg={getErrorMessage(query.error)} />;
  }
  return (
    <Application>
      <ToastNotificationProvider>
        <NotaryAppNavigationBars />
        <AppMain>
          <ConfigTable config={query.data} />
        </AppMain>
        <NotaryAppStatus />
      </ToastNotificationProvider>
    </Application>
  );
}

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
