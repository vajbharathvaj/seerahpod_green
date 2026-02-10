import React, { useMemo, useState } from 'react';
import {
  Users as UsersIcon,
  UserCheck,
  Crown,
  BadgePercent,
  TrendingUp,
  TrendingDown,
  Activity,
  Clock,
  Repeat,
  Heart,
  Sparkles,
  Flame,
  Moon,
  PlayCircle,
  Globe,
  Smartphone,
  Monitor
} from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from 'recharts';

const kpiCards = [
  {
    label: 'Total Users',
    value: '128,492',
    delta: '+6.2%',
    icon: UsersIcon,
    color: '#3B82F6'
  },
  {
    label: 'Active Users (30d)',
    value: '82,419',
    delta: '+3.4%',
    icon: UserCheck,
    color: '#1DB954'
  },
  {
    label: 'Premium Users',
    value: '18,906',
    delta: '+9.1%',
    icon: Crown,
    color: '#F59E0B'
  },
  {
    label: 'Conversion Rate',
    value: '14.7%',
    delta: '+1.8%',
    icon: BadgePercent,
    color: '#8B5CF6'
  }
];

const conversionSeries = {
  Daily: [
    { label: 'Mon', conversions: 142 },
    { label: 'Tue', conversions: 168 },
    { label: 'Wed', conversions: 151 },
    { label: 'Thu', conversions: 196 },
    { label: 'Fri', conversions: 211 },
    { label: 'Sat', conversions: 184 },
    { label: 'Sun', conversions: 172 }
  ],
  Weekly: [
    { label: 'W1', conversions: 920 },
    { label: 'W2', conversions: 1040 },
    { label: 'W3', conversions: 980 },
    { label: 'W4', conversions: 1190 },
    { label: 'W5', conversions: 1285 },
    { label: 'W6', conversions: 1340 }
  ],
  Monthly: [
    { label: 'May', conversions: 3450 },
    { label: 'Jun', conversions: 3890 },
    { label: 'Jul', conversions: 4120 },
    { label: 'Aug', conversions: 4580 },
    { label: 'Sep', conversions: 4860 },
    { label: 'Oct', conversions: 5120 }
  ]
};

const funnelStages = [
  { label: 'Free Users', value: '128,492', percent: 100 },
  { label: 'Trial Users', value: '24,870', percent: 19 },
  { label: 'Premium Users', value: '18,906', percent: 14.7 }
];

const engagementMetrics = [
  { label: 'Avg Session Time', value: '18m 42s', status: 'Healthy', icon: Clock, color: '#1DB954' },
  { label: 'Completion Rate', value: '72%', status: 'Rising', icon: Activity, color: '#3B82F6' },
  { label: 'Repeat Listeners', value: '44%', status: 'Monitor', icon: Repeat, color: '#F59E0B' },
  { label: 'Save Rate', value: '21%', status: 'Rising', icon: Heart, color: '#EC4899' }
];

const activityBreakdown = [
  { label: 'New Users (7 days)', value: '6,420', change: '+5.8%' },
  { label: 'New Users (30 days)', value: '21,908', change: '+7.1%' },
  { label: 'Top Converting Content', value: '"Seerah Season 3"', change: '+12.4%' },
  { label: 'Churn Risk Signals', value: '8.2% of actives', change: '-0.6%' }
];

const platformSplit = [
  { label: 'Mobile', value: '62%', icon: Smartphone },
  { label: 'Desktop', value: '25%', icon: Monitor },
  { label: 'Web', value: '13%', icon: Globe }
];

const premiumInsights = [
  {
    title: 'Premium users complete 2.3x more content',
    detail: 'Completion intensity peaks after the second week of premium access.',
    icon: Sparkles
  },
  {
    title: 'New releases drive highest conversion',
    detail: 'Launch weeks show a 28% lift in trial-to-premium upgrades.',
    icon: Flame
  },
  {
    title: 'Evening listening sessions convert best',
    detail: '7–10 PM local time delivers the strongest upgrade velocity.',
    icon: Moon
  }
];

export function Users() {
  const { theme } = useTheme();
  const [period, setPeriod] = useState<'Daily' | 'Weekly' | 'Monthly'>('Weekly');

  const chartData = useMemo(() => conversionSeries[period], [period]);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold mb-2">User Insights</h1>
        <p className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>
          Track growth, engagement, and premium conversion performance.
        </p>
      </div>

      {/* KPI Bento Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {kpiCards.map((card) => {
          const Icon = card.icon;
          return (
            <div
              key={card.label}
              className={`p-6 rounded-2xl border transition-all hover:scale-105 relative overflow-hidden ${
                theme === 'dark'
                  ? 'bg-[#1a1a1a] border-gray-800 hover:border-gray-700'
                  : 'bg-white border-gray-200 hover:border-gray-300 shadow-sm'
              }`}
            >
              <div
                className="absolute -top-12 -right-12 w-32 h-32 rounded-full blur-2xl opacity-30"
                style={{ backgroundColor: card.color }}
              />
              <div className="flex items-start justify-between mb-4">
                <div className="p-3 rounded-xl" style={{ backgroundColor: `${card.color}20` }}>
                  <Icon className="w-6 h-6" style={{ color: card.color }} />
                </div>
                <div className="flex items-center gap-1 text-[#1DB954] text-sm">
                  <TrendingUp className="w-4 h-4" />
                  <span>{card.delta}</span>
                </div>
              </div>
              <h3 className={`text-3xl font-bold mb-1 ${theme === 'dark' ? 'text-white' : 'text-gray-900'}`}>
                {card.value}
              </h3>
              <p className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>{card.label}</p>
            </div>
          );
        })}
      </div>

      {/* Main Analytics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div
          className={`lg:col-span-2 p-6 rounded-2xl border ${
            theme === 'dark' ? 'bg-[#1a1a1a] border-gray-800' : 'bg-white border-gray-200 shadow-sm'
          }`}
        >
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
            <div>
              <h2 className="text-xl font-semibold">Premium Conversions</h2>
              <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                Conversion volume across selected period
              </p>
            </div>
            <div className={`flex items-center gap-2 p-1 rounded-xl ${theme === 'dark' ? 'bg-gray-800' : 'bg-gray-100'}`}>
              {(['Daily', 'Weekly', 'Monthly'] as const).map((option) => (
                <button
                  key={option}
                  onClick={() => setPeriod(option)}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                    period === option
                      ? 'bg-[#1DB954] text-white'
                      : theme === 'dark'
                      ? 'text-gray-300 hover:text-white'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  {option}
                </button>
              ))}
            </div>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="conversionFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#1DB954" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#1DB954" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={theme === 'dark' ? '#333' : '#e5e7eb'} />
              <XAxis
                dataKey="label"
                stroke={theme === 'dark' ? '#666' : '#999'}
                style={{ fontSize: '12px' }}
              />
              <YAxis stroke={theme === 'dark' ? '#666' : '#999'} style={{ fontSize: '12px' }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: theme === 'dark' ? '#1a1a1a' : '#fff',
                  border: `1px solid ${theme === 'dark' ? '#333' : '#e5e7eb'}`,
                  borderRadius: '8px',
                  color: theme === 'dark' ? '#fff' : '#000'
                }}
              />
              <Area
                type="monotone"
                dataKey="conversions"
                stroke="#1DB954"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#conversionFill)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div
          className={`p-6 rounded-2xl border ${
            theme === 'dark' ? 'bg-[#1a1a1a] border-gray-800' : 'bg-white border-gray-200 shadow-sm'
          }`}
        >
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-xl font-semibold">Conversion Funnel</h2>
              <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                Drop-offs across the journey
              </p>
            </div>
            <PlayCircle className="w-5 h-5 text-[#1DB954]" />
          </div>
          <div className="space-y-4">
            {funnelStages.map((stage, index) => (
              <div key={stage.label}>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">{stage.label}</span>
                  <span className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                    {stage.value} · {stage.percent}%
                  </span>
                </div>
                <div className={`h-3 rounded-full ${theme === 'dark' ? 'bg-gray-800' : 'bg-gray-100'} overflow-hidden`}>
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${stage.percent}%`,
                      background: `linear-gradient(90deg, #1DB954, ${index === 0 ? '#1DB954' : '#3B82F6'})`
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
          <div className={`mt-6 p-4 rounded-xl ${theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-50'}`}>
            <div className="flex items-center justify-between text-sm">
              <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>Trial to Premium</span>
              <span className="text-[#1DB954] font-medium">76.0%</span>
            </div>
            <div className="flex items-center justify-between text-sm mt-2">
              <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>Free to Trial</span>
              <span className={theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}>19.3%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Engagement Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {engagementMetrics.map((metric) => {
          const Icon = metric.icon;
          const statusColor =
            metric.status === 'Healthy'
              ? 'text-[#1DB954]'
              : metric.status === 'Rising'
              ? 'text-blue-400'
              : 'text-amber-400';
          return (
            <div
              key={metric.label}
              className={`p-5 rounded-2xl border ${
                theme === 'dark' ? 'bg-[#1a1a1a] border-gray-800' : 'bg-white border-gray-200 shadow-sm'
              }`}
            >
              <div className="flex items-center justify-between mb-4">
                <div className="p-2 rounded-lg" style={{ backgroundColor: `${metric.color}20` }}>
                  <Icon className="w-5 h-5" style={{ color: metric.color }} />
                </div>
                <span className={`text-xs font-semibold ${statusColor}`}>{metric.status}</span>
              </div>
              <p className="text-2xl font-bold mb-1">{metric.value}</p>
              <p className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>{metric.label}</p>
            </div>
          );
        })}
      </div>

      {/* User Activity Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div
          className={`lg:col-span-2 p-6 rounded-2xl border ${
            theme === 'dark' ? 'bg-[#1a1a1a] border-gray-800' : 'bg-white border-gray-200 shadow-sm'
          }`}
        >
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold">User Activity Breakdown</h2>
            <div className="flex items-center gap-2 text-sm text-[#1DB954]">
              <TrendingUp className="w-4 h-4" />
              <span>Strong momentum</span>
            </div>
          </div>
          <div className="space-y-4">
            {activityBreakdown.map((item) => (
              <div
                key={item.label}
                className={`flex items-center justify-between p-4 rounded-xl ${
                  theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-50'
                }`}
              >
                <div>
                  <p className="font-medium">{item.label}</p>
                  <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>{item.value}</p>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  {item.change.startsWith('-') ? (
                    <TrendingDown className="w-4 h-4 text-amber-400" />
                  ) : (
                    <TrendingUp className="w-4 h-4 text-[#1DB954]" />
                  )}
                  <span className={item.change.startsWith('-') ? 'text-amber-400' : 'text-[#1DB954]'}>
                    {item.change}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div
          className={`p-6 rounded-2xl border ${
            theme === 'dark' ? 'bg-[#1a1a1a] border-gray-800' : 'bg-white border-gray-200 shadow-sm'
          }`}
        >
          <h2 className="text-xl font-semibold mb-6">Region & Platform Split</h2>
          <div className="space-y-4">
            {platformSplit.map((item) => {
              const Icon = item.icon;
              return (
                <div key={item.label} className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${theme === 'dark' ? 'bg-gray-800' : 'bg-gray-100'}`}>
                      <Icon className="w-4 h-4 text-[#1DB954]" />
                    </div>
                    <span className="text-sm font-medium">{item.label}</span>
                  </div>
                  <span className="text-sm font-semibold">{item.value}</span>
                </div>
              );
            })}
          </div>
          <div className={`mt-6 p-4 rounded-xl ${theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-50'}`}>
            <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>Top Region</p>
            <p className="text-2xl font-bold">North America</p>
            <p className={`text-sm ${theme === 'dark' ? 'text-gray-500' : 'text-gray-600'}`}>
              41% of premium upgrades
            </p>
          </div>
        </div>
      </div>

      {/* Premium Performance Insights */}
      <div
        className={`p-6 rounded-2xl border ${
          theme === 'dark' ? 'bg-[#1a1a1a] border-gray-800' : 'bg-white border-gray-200 shadow-sm'
        }`}
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold">Premium Performance Insights</h2>
          <div className="flex items-center gap-2 text-sm">
            <span className="text-[#1DB954] font-medium">Executive summary</span>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {premiumInsights.map((insight) => {
            const Icon = insight.icon;
            return (
              <div
                key={insight.title}
                className={`p-4 rounded-xl border ${
                  theme === 'dark' ? 'border-gray-800 bg-gray-800/40' : 'border-gray-200 bg-gray-50'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className="p-2 rounded-lg bg-[#1DB954]/15">
                    <Icon className="w-4 h-4 text-[#1DB954]" />
                  </div>
                  <div>
                    <p className="font-semibold mb-1">{insight.title}</p>
                    <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                      {insight.detail}
                    </p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
