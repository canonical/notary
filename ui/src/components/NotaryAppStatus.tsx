import { AppStatus } from "@canonical/react-components";

export default function NotaryAppStatus() {
  return (
    <AppStatus>
      <span className="p-text--small u-no-margin--bottom">
        Version {process.env.VERSION}
      </span>
    </AppStatus>
  )
}