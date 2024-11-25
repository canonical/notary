"use client"
import '@/globals.scss'
import Navigation from "@/components/nav";
import { AuthProvider } from "@/hooks/useAuth";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const queryClient = new QueryClient()
export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <body>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <Navigation>
            {children}
          </Navigation>
        </AuthProvider>
      </QueryClientProvider>
    </body>
  );
}