import type { Metadata } from "next";
import "@/globals.scss";
import NotaryLayout from "@/components/NotaryLayout";

export const metadata: Metadata = {
  title: "Notary",
  description: "A certificate management application",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <link rel="icon" href="/favicon.ico" sizes="any" />
      </head>
      <NotaryLayout>{children}</NotaryLayout>
    </html>
  );
}
