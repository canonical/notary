import { AppStatus } from "@canonical/react-components";

export default function NotaryAppStatus() {
  return (
    <AppStatus>
      <span
        className="p-text--small u-no-margin--bottom"
        style={{ paddingLeft: "10px" }}
      >
        Version {import.meta.env.NOTARY_APP_VERSION}
      </span>
    </AppStatus>
  );
}
