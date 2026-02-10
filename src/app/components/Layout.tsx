import React, { useState } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router';
import {
  LayoutDashboard,
  Music,
  ListMusic,
  Folder,
  Users,
  Lock,
  Sparkles,
  BarChart3,
  Settings,
  Search,
  Bell,
  ChevronLeft,
  ChevronRight,
  LogOut,
  User,
  Moon,
  Sun,
} from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';
import * as DropdownMenu from '@radix-ui/react-dropdown-menu';
import SeerahLogo from '../../assets/seerah-logo.svg';
import SeerahPodText from '../../assets/serrahpodtext.svg';

interface NavItem {
  path: string;
  label: string;
  icon: React.ReactNode;
}

const navItems: NavItem[] = [
  { path: '/', label: 'Dashboard', icon: <LayoutDashboard className="w-5 h-5" /> },
  { path: '/audio', label: 'Audio Content', icon: <Music className="w-5 h-5" /> },
  { path: '/playlists', label: 'Playlists', icon: <ListMusic className="w-5 h-5" /> },
  { path: '/users', label: 'Users & Roles', icon: <Users className="w-5 h-5" /> },
  { path: '/paywall', label: 'Paywall & Premium', icon: <Lock className="w-5 h-5" /> },
  { path: '/recommendations', label: 'Recommendations', icon: <Sparkles className="w-5 h-5" /> },
  { path: '/settings', label: 'Settings', icon: <Settings className="w-5 h-5" /> },
];

export function Layout() {
  const navigate = useNavigate();
  const location = useLocation();
  const { theme, toggleTheme } = useTheme();
  const [collapsed, setCollapsed] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const handleLogout = () => {
    navigate('/login');
  };

  return (
    <div className={`min-h-screen ${
      theme === 'dark' ? 'bg-[#0a0a0a] text-white' : 'bg-gray-50 text-gray-900'
    }`}>
      {/* Sidebar */}
      <aside
        className={`fixed left-0 top-0 h-screen transition-all duration-300 z-20 ${
          collapsed ? 'w-20' : 'w-64'
        } ${theme === 'dark' ? 'bg-[#121212] border-r border-gray-800' : 'bg-white border-r border-gray-200'}`}
      >
        {/* Logo */}
        <div className="h-16 flex items-center justify-between px-5 border-b border-current border-opacity-10">
          <div className={`flex items-center gap-3 ${collapsed ? 'mx-auto' : ''}`}>
            <img
              src={SeerahLogo}
              alt="Seerah logo"
              className={`${collapsed ? 'h-9 w-auto' : 'h-10 w-auto'} select-none`}
              draggable={false}
            />
            <img
              src={SeerahPodText}
              alt="Seerah pod"
              className={`${collapsed ? 'h-9 w-auto' : 'h-10 w-auto'} select-none`}
              draggable={false}
            />
          </div>
        </div>

        {/* Navigation */}
        <nav className="mt-6 px-3">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path;
            return (
              <button
                key={item.path}
                onClick={() => navigate(item.path)}
                className={`w-full flex items-center gap-3 px-3 py-3 rounded-lg mb-1 transition-all ${
                  isActive
                    ? 'bg-[#1DB954] text-white shadow-lg shadow-[#1DB954]/20'
                    : theme === 'dark'
                    ? 'text-gray-400 hover:text-white hover:bg-white/5'
                    : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                }`}
              >
                {item.icon}
                {!collapsed && <span className="font-medium">{item.label}</span>}
              </button>
            );
          })}
        </nav>

        {/* Collapse Toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className={`absolute bottom-6 left-1/2 -translate-x-1/2 p-2 rounded-lg ${
            theme === 'dark'
              ? 'bg-gray-800 hover:bg-gray-700 text-gray-400'
              : 'bg-gray-200 hover:bg-gray-300 text-gray-600'
          }`}
        >
          {collapsed ? <ChevronRight className="w-5 h-5" /> : <ChevronLeft className="w-5 h-5" />}
        </button>
      </aside>

      {/* Main Content */}
      <div className={`transition-all duration-300 ${collapsed ? 'ml-20' : 'ml-64'}`}>
        {/* Header */}
        <header className={`h-16 border-b sticky top-0 z-10 backdrop-blur-sm ${
          theme === 'dark'
            ? 'bg-[#0a0a0a]/80 border-gray-800'
            : 'bg-white/80 border-gray-200'
        }`}>
          <div className="h-full flex items-center justify-between px-8">
            {/* Search Bar */}
            <div className="flex-1 max-w-md">
              <div className="relative">
                <Search className={`absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 ${
                  theme === 'dark' ? 'text-gray-500' : 'text-gray-400'
                }`} />
                <input
                  type="text"
                  placeholder="Search..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className={`w-full pl-10 pr-4 py-2 rounded-full border transition-all outline-none ${
                    theme === 'dark'
                      ? 'bg-[#1a1a1a] border-gray-800 text-white placeholder-gray-600 focus:border-[#1DB954]'
                      : 'bg-gray-100 border-gray-300 text-gray-900 placeholder-gray-500 focus:border-[#1DB954]'
                  }`}
                />
              </div>
            </div>

            {/* Right Side Actions */}
            <div className="flex items-center gap-4">
              {/* Theme Toggle */}
              <button
                onClick={toggleTheme}
                className={`p-2 rounded-full transition-all ${
                  theme === 'dark'
                    ? 'hover:bg-gray-800 text-gray-400 hover:text-white'
                    : 'hover:bg-gray-200 text-gray-600 hover:text-gray-900'
                }`}
              >
                {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
              </button>

              {/* Notifications */}
              <button className={`p-2 rounded-full relative transition-all ${
                theme === 'dark'
                  ? 'hover:bg-gray-800 text-gray-400 hover:text-white'
                  : 'hover:bg-gray-200 text-gray-600 hover:text-gray-900'
              }`}>
                <Bell className="w-5 h-5" />
                <span className="absolute top-1 right-1 w-2 h-2 bg-[#1DB954] rounded-full" />
              </button>

              {/* User Dropdown */}
              <DropdownMenu.Root>
                <DropdownMenu.Trigger asChild>
                  <button className={`flex items-center gap-3 px-3 py-2 rounded-full transition-all ${
                    theme === 'dark'
                      ? 'hover:bg-gray-800'
                      : 'hover:bg-gray-200'
                  }`}>
                    <div className="w-8 h-8 rounded-full bg-gradient-to-br from-[#1DB954] to-[#1ed760] flex items-center justify-center">
                      <User className="w-4 h-4 text-white" />
                    </div>
                  </button>
                </DropdownMenu.Trigger>

                <DropdownMenu.Portal>
                  <DropdownMenu.Content
                    className={`min-w-56 rounded-xl p-2 shadow-xl border ${
                      theme === 'dark'
                        ? 'bg-[#1a1a1a] border-gray-800'
                        : 'bg-white border-gray-200'
                    }`}
                    sideOffset={5}
                  >
                    <DropdownMenu.Item
                      className={`px-3 py-2 rounded-lg cursor-pointer outline-none ${
                        theme === 'dark'
                          ? 'text-gray-300 hover:bg-gray-800'
                          : 'text-gray-700 hover:bg-gray-100'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <User className="w-4 h-4" />
                        Profile
                      </div>
                    </DropdownMenu.Item>
                    <DropdownMenu.Item
                      className={`px-3 py-2 rounded-lg cursor-pointer outline-none ${
                        theme === 'dark'
                          ? 'text-gray-300 hover:bg-gray-800'
                          : 'text-gray-700 hover:bg-gray-100'
                      }`}
                      onClick={() => navigate('/settings')}
                    >
                      <div className="flex items-center gap-2">
                        <Settings className="w-4 h-4" />
                        Settings
                      </div>
                    </DropdownMenu.Item>
                    <DropdownMenu.Separator className={`my-1 h-px ${
                      theme === 'dark' ? 'bg-gray-800' : 'bg-gray-200'
                    }`} />
                    <DropdownMenu.Item
                      className="px-3 py-2 rounded-lg cursor-pointer outline-none text-red-500 hover:bg-red-500/10"
                      onClick={handleLogout}
                    >
                      <div className="flex items-center gap-2">
                        <LogOut className="w-4 h-4" />
                        Logout
                      </div>
                    </DropdownMenu.Item>
                  </DropdownMenu.Content>
                </DropdownMenu.Portal>
              </DropdownMenu.Root>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
