import type { Metadata } from "next";
import './globals.scss'
import Navigation from "@/app/nav";


export const metadata: Metadata = {
  title: "GoCert",
  description: "A certificate management application",
};


export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
          <Navigation>
            {children}
          </Navigation>
      </body>
    </html>
  );
}