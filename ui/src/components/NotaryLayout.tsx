"use client";
import { useLoginRedirect } from "@/hooks/useLoginRedirect";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const queryClient = new QueryClient();
export default function NotaryLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <QueryClientProvider client={queryClient}>
      <GlobalHooks />
      {children}
    </QueryClientProvider>
  );
}

function GlobalHooks() {
  useLoginRedirect();
  return <></>;
}
