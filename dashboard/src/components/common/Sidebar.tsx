import { NavLink } from 'react-router-dom';

const links = [
  { to: '/', label: 'Dashboard' },
  { to: '/rules', label: 'Rules' },
  { to: '/logs', label: 'Logs' },
  { to: '/blocklist', label: 'Blocklist' },
];

export default function Sidebar() {
  return (
    <aside className="w-64 bg-gray-800 min-h-screen p-4">
      <nav className="space-y-2">
        {links.map(link => (
          <NavLink
            key={link.to}
            to={link.to}
            className={({ isActive }) =>
              `block p-3 rounded transition ${isActive ? 'bg-blue-600' : 'hover:bg-gray-700'}`
            }
          >
            {link.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}