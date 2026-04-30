import { AppStatus } from "@canonical/react-components";

export default function NotaryAppStatus() {
  return (
    <AppStatus>
      <span
        className="p-text--small u-no-margin--bottom"
        style={{ paddingLeft: "10px" }}
      >
        Version {process.env.VERSION}
      </span>
    </AppStatus>
  );
}
