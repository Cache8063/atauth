import { useQuery } from '@tanstack/react-query';
import { Header } from '../components/Layout';
import { api } from '../api/client';

export function DashboardPage() {
  const { data: stats, isLoading, error } = useQuery({
    queryKey: ['stats'],
    queryFn: () => api.getStats(),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  return (
    <div>
      <Header title="Dashboard" />

      <div className="p-6">
        {isLoading ? (
          <div className="text-gray-500 dark:text-gray-400">Loading statistics...</div>
        ) : error ? (
          <div className="p-4 bg-red-50 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded-md">
            Failed to load statistics
          </div>
        ) : stats ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <StatCard
              title="Total Apps"
              value={stats.apps_count}
              subtitle="Legacy + OIDC"
            />
            <StatCard
              title="OIDC Clients"
              value={stats.oidc_clients_count}
              subtitle="OAuth 2.0 / OIDC"
            />
            <StatCard
              title="Active Sessions"
              value={stats.active_sessions_count}
              subtitle="Currently logged in"
            />
            <StatCard
              title="Unique Users"
              value={stats.users_count}
              subtitle="Registered DIDs"
            />
            <StatCard
              title="Passkeys"
              value={stats.passkeys_count}
              subtitle="WebAuthn credentials"
            />
            <StatCard
              title="MFA Enabled"
              value={stats.mfa_enabled_count}
              subtitle="TOTP configured"
            />
            <StatCard
              title="Verified Emails"
              value={stats.verified_emails_count}
              subtitle="Confirmed addresses"
            />
          </div>
        ) : null}

        <div className="mt-8">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Quick Actions
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <QuickAction
              title="Register New App"
              description="Add a legacy HMAC-signed app"
              href="/apps"
            />
            <QuickAction
              title="Create OIDC Client"
              description="Register an OpenID Connect client"
              href="/oidc-clients"
            />
            <QuickAction
              title="Rotate Signing Keys"
              description="Generate new JWT signing keys"
              href="/keys"
            />
          </div>
        </div>
      </div>
    </div>
  );
}

interface StatCardProps {
  title: string;
  value: number;
  subtitle: string;
}

function StatCard({ title, value, subtitle }: StatCardProps) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">
        {title}
      </h4>
      <p className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">
        {value.toLocaleString()}
      </p>
      <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
        {subtitle}
      </p>
    </div>
  );
}

interface QuickActionProps {
  title: string;
  description: string;
  href: string;
}

function QuickAction({ title, description, href }: QuickActionProps) {
  return (
    <a
      href={href}
      className="block p-4 bg-white dark:bg-gray-800 rounded-lg shadow hover:shadow-md transition-shadow"
    >
      <h4 className="font-medium text-gray-900 dark:text-white">{title}</h4>
      <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
        {description}
      </p>
    </a>
  );
}
