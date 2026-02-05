import { useAuthStore } from '../../stores/auth';

interface HeaderProps {
  title: string;
}

export function Header({ title }: HeaderProps) {
  const logout = useAuthStore((s) => s.logout);

  return (
    <header className="h-16 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between px-6">
      <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
        {title}
      </h2>

      <button
        onClick={logout}
        className="text-sm text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white transition-colors"
      >
        Sign Out
      </button>
    </header>
  );
}
