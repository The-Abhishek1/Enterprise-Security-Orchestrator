// src/app/layout.tsx
import './globals.css';
import { AuthProvider } from '@/lib/auth-context';
import Sidebar from '@/components/layout/sidebar';
import AuthGuard from '@/components/layout/auth-guard';

export const metadata = { title: 'ESO — Security Orchestrator' };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          <AuthGuard>
            <div className="flex h-screen">
              <Sidebar />
              <main className="flex-1 overflow-y-auto p-4 md:p-6 lg:p-8">{children}</main>
            </div>
          </AuthGuard>
        </AuthProvider>
      </body>
    </html>
  );
}
