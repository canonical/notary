import { useLoginRedirect } from "@/hooks/useLoginRedirect";

export default function NotaryAppLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <>
      <GlobalHooks />
      {children}
    </>
  );
}

function GlobalHooks() {
  useLoginRedirect();
  return <></>;
}
