import type { Metadata } from 'next';
import './styles.css';
export const metadata: Metadata = { title: 'Security Operations', description: 'Tenant-scoped security monitoring and incident investigation' };
export default function Layout({ children }: { children: React.ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
