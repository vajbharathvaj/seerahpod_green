import React from 'react';
import { Music, ListMusic, Users, Crown, TrendingUp, Upload, Plus, Play } from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const kpiData = [
  { label: 'Total Tracks', value: '12,547', trend: '+12%', icon: Music, color: '#1DB954' },
  { label: 'Total Playlists', value: '1,834', trend: '+8%', icon: ListMusic, color: '#3B82F6' },
  { label: 'Active Users', value: '45,892', trend: '+23%', icon: Users, color: '#F59E0B' },
  { label: 'Premium Users', value: '8,234', trend: '+18%', icon: Crown, color: '#8B5CF6' },
];

const uploadActivityData = [
  { date: 'Mon', uploads: 45 },
  { date: 'Tue', uploads: 52 },
  { date: 'Wed', uploads: 38 },
  { date: 'Thu', uploads: 65 },
  { date: 'Fri', uploads: 78 },
  { date: 'Sat', uploads: 42 },
  { date: 'Sun', uploads: 35 },
];

const engagementData = [
  { month: 'Jan', plays: 4200, users: 3200 },
  { month: 'Feb', plays: 5100, users: 3800 },
  { month: 'Mar', plays: 6300, users: 4500 },
  { month: 'Apr', plays: 7800, users: 5200 },
  { month: 'May', plays: 8900, users: 6100 },
  { month: 'Jun', plays: 9500, users: 6800 },
];

const recentUploads = [
  { title: 'The Prophet\'s Journey', artist: 'Sheikh Ahmad', duration: '45:23', cover: '🎙️' },
  { title: 'Stories of Companions', artist: 'Dr. Sarah Khan', duration: '32:15', cover: '📚' },
  { title: 'Islamic History', artist: 'Prof. Hassan', duration: '58:40', cover: '🕌' },
  { title: 'Quranic Reflections', artist: 'Imam Abdullah', duration: '28:12', cover: '📖' },
];

const topPlayed = [
  { rank: 1, title: 'Life of the Prophet', plays: 125400, change: '+15%' },
  { rank: 2, title: 'Ramadan Special', plays: 98200, change: '+12%' },
  { rank: 3, title: 'Inspiring Stories', plays: 87600, change: '+8%' },
  { rank: 4, title: 'Daily Reflections', plays: 76300, change: '+5%' },
  { rank: 5, title: 'Islamic Wisdom', plays: 65100, change: '+3%' },
];

export function Dashboard() {
  const { theme } = useTheme();

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold mb-2">Dashboard</h1>
        <p className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>
          Welcome back! Here's what's happening with your platform.
        </p>
      </div>

      {/* KPI Cards - Bento Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {kpiData.map((kpi) => {
          const Icon = kpi.icon;
          return (
            <div
              key={kpi.label}
              className={`p-6 rounded-2xl border transition-all hover:scale-105 ${
                theme === 'dark'
                  ? 'bg-[#1a1a1a] border-gray-800 hover:border-gray-700'
                  : 'bg-white border-gray-200 hover:border-gray-300 shadow-sm'
              }`}
            >
              <div className="flex items-start justify-between mb-4">
                <div
                  className="p-3 rounded-xl"
                  style={{ backgroundColor: `${kpi.color}20` }}
                >
                  <Icon className="w-6 h-6" style={{ color: kpi.color }} />
                </div>
                <div className="flex items-center gap-1 text-[#1DB954] text-sm">
                  <TrendingUp className="w-4 h-4" />
                  <span>{kpi.trend}</span>
                </div>
              </div>
              <h3 className={`text-3xl font-bold mb-1 ${
                theme === 'dark' ? 'text-white' : 'text-gray-900'
              }`}>
                {kpi.value}
              </h3>
              <p className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>
                {kpi.label}
              </p>
            </div>
          );
        })}
      </div>

      {/* Main Bento Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Upload Activity Chart - 2 columns */}
        <div className={`lg:col-span-2 p-6 rounded-2xl border ${
          theme === 'dark'
            ? 'bg-[#1a1a1a] border-gray-800'
            : 'bg-white border-gray-200 shadow-sm'
        }`}>
          <h2 className="text-xl font-semibold mb-6">Upload Activity</h2>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={uploadActivityData}>
              <CartesianGrid strokeDasharray="3 3" stroke={theme === 'dark' ? '#333' : '#e5e7eb'} />
              <XAxis
                dataKey="date"
                stroke={theme === 'dark' ? '#666' : '#999'}
                style={{ fontSize: '12px' }}
              />
              <YAxis
                stroke={theme === 'dark' ? '#666' : '#999'}
                style={{ fontSize: '12px' }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: theme === 'dark' ? '#1a1a1a' : '#fff',
                  border: `1px solid ${theme === 'dark' ? '#333' : '#e5e7eb'}`,
                  borderRadius: '8px',
                  color: theme === 'dark' ? '#fff' : '#000',
                }}
              />
              <Bar dataKey="uploads" fill="#1DB954" radius={[8, 8, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Quick Actions */}
        <div className={`p-6 rounded-2xl border ${
          theme === 'dark'
            ? 'bg-[#1a1a1a] border-gray-800'
            : 'bg-white border-gray-200 shadow-sm'
        }`}>
          <h2 className="text-xl font-semibold mb-6">Quick Actions</h2>
          <div className="space-y-3">
            <button className="w-full flex items-center justify-center gap-2 bg-[#1DB954] hover:bg-[#1ed760] text-white py-3 rounded-xl font-medium transition-all">
              <Upload className="w-5 h-5" />
              Upload Audio
            </button>
            <button className={`w-full flex items-center justify-center gap-2 py-3 rounded-xl font-medium transition-all ${
              theme === 'dark'
                ? 'bg-gray-800 hover:bg-gray-700 text-white'
                : 'bg-gray-100 hover:bg-gray-200 text-gray-900'
            }`}>
              <Plus className="w-5 h-5" />
              Create Playlist
            </button>
          </div>

          {/* Mini Stats */}
          <div className="mt-8 space-y-4">
            <div className={`p-4 rounded-xl ${
              theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-50'
            }`}>
              <p className={`text-sm mb-1 ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                Total Storage Used
              </p>
              <p className="text-2xl font-bold">234 GB</p>
              <div className="mt-2 h-2 bg-gray-700 rounded-full overflow-hidden">
                <div className="h-full bg-[#1DB954] w-[65%]" />
              </div>
            </div>
            <div className={`p-4 rounded-xl ${
              theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-50'
            }`}>
              <p className={`text-sm mb-1 ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                Bandwidth This Month
              </p>
              <p className="text-2xl font-bold">1.2 TB</p>
            </div>
          </div>
        </div>

        {/* Recently Uploaded */}
        <div className={`p-6 rounded-2xl border ${
          theme === 'dark'
            ? 'bg-[#1a1a1a] border-gray-800'
            : 'bg-white border-gray-200 shadow-sm'
        }`}>
          <h2 className="text-xl font-semibold mb-6">Recently Uploaded</h2>
          <div className="space-y-3">
            {recentUploads.map((track, idx) => (
              <div
                key={idx}
                className={`flex items-center gap-3 p-3 rounded-xl transition-all hover:scale-105 cursor-pointer ${
                  theme === 'dark' ? 'hover:bg-gray-800' : 'hover:bg-gray-50'
                }`}
              >
                <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-[#1DB954] to-[#1ed760] flex items-center justify-center text-2xl">
                  {track.cover}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="font-medium truncate">{track.title}</p>
                  <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                    {track.artist}
                  </p>
                </div>
                <span className={`text-sm ${theme === 'dark' ? 'text-gray-500' : 'text-gray-500'}`}>
                  {track.duration}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Played Tracks */}
        <div className={`lg:col-span-2 p-6 rounded-2xl border ${
          theme === 'dark'
            ? 'bg-[#1a1a1a] border-gray-800'
            : 'bg-white border-gray-200 shadow-sm'
        }`}>
          <h2 className="text-xl font-semibold mb-6">Top Played Tracks</h2>
          <div className="space-y-3">
            {topPlayed.map((track) => (
              <div
                key={track.rank}
                className={`flex items-center gap-4 p-4 rounded-xl transition-all ${
                  theme === 'dark' ? 'hover:bg-gray-800' : 'hover:bg-gray-50'
                }`}
              >
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center font-bold ${
                  track.rank === 1
                    ? 'bg-[#1DB954] text-white'
                    : theme === 'dark'
                    ? 'bg-gray-800 text-gray-400'
                    : 'bg-gray-100 text-gray-600'
                }`}>
                  {track.rank}
                </div>
                <div className="flex-1">
                  <p className="font-medium">{track.title}</p>
                  <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                    {track.plays.toLocaleString()} plays
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[#1DB954] text-sm">{track.change}</span>
                  <button className={`p-2 rounded-full transition-all ${
                    theme === 'dark' ? 'hover:bg-gray-700' : 'hover:bg-gray-200'
                  }`}>
                    <Play className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* User Engagement Chart */}
      <div className={`p-6 rounded-2xl border ${
        theme === 'dark'
          ? 'bg-[#1a1a1a] border-gray-800'
          : 'bg-white border-gray-200 shadow-sm'
      }`}>
        <h2 className="text-xl font-semibold mb-6">User Engagement Trends</h2>
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={engagementData}>
            <defs>
              <linearGradient id="colorPlays" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#1DB954" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#1DB954" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorUsers" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#3B82F6" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke={theme === 'dark' ? '#333' : '#e5e7eb'} />
            <XAxis
              dataKey="month"
              stroke={theme === 'dark' ? '#666' : '#999'}
              style={{ fontSize: '12px' }}
            />
            <YAxis
              stroke={theme === 'dark' ? '#666' : '#999'}
              style={{ fontSize: '12px' }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: theme === 'dark' ? '#1a1a1a' : '#fff',
                border: `1px solid ${theme === 'dark' ? '#333' : '#e5e7eb'}`,
                borderRadius: '8px',
                color: theme === 'dark' ? '#fff' : '#000',
              }}
            />
            <Area
              type="monotone"
              dataKey="plays"
              stroke="#1DB954"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#colorPlays)"
            />
            <Area
              type="monotone"
              dataKey="users"
              stroke="#3B82F6"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#colorUsers)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
