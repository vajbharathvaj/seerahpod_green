import React, { useState } from 'react';
import { Lock, Unlock, Crown, TrendingUp, DollarSign } from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';
import * as Switch from '@radix-ui/react-switch';

interface PremiumContent {
  id: string;
  title: string;
  type: 'track' | 'playlist';
  subscribers: number;
  revenue: string;
  isLocked: boolean;
}

const mockPremiumContent: PremiumContent[] = [
  { id: '1', title: 'Premium Seerah Series', type: 'playlist', subscribers: 1240, revenue: '$2,480', isLocked: true },
  { id: '2', title: 'Ramadan Special Collection', type: 'playlist', subscribers: 890, revenue: '$1,780', isLocked: true },
  { id: '3', title: 'Advanced Islamic Studies', type: 'track', subscribers: 560, revenue: '$1,120', isLocked: true },
  { id: '4', title: 'Exclusive Lectures', type: 'playlist', subscribers: 2100, revenue: '$4,200', isLocked: true },
];

export function Paywall() {
  const { theme } = useTheme();
  const [premiumContent, setPremiumContent] = useState<PremiumContent[]>(mockPremiumContent);
  const [premiumRules, setPremiumRules] = useState({
    subscriptionPrice: '9.99',
    trialDays: '7',
    autoLockNewContent: false,
    allowGifting: true,
  });

  const toggleLock = (id: string) => {
    setPremiumContent(premiumContent.map(content =>
      content.id === id ? { ...content, isLocked: !content.isLocked } : content
    ));
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold mb-2">Paywall & Premium</h1>
        <p className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>
          Manage premium content, subscriptions, and monetization settings.
        </p>
      </div>

      {/* Revenue Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className={`p-6 rounded-2xl border ${
          theme === 'dark'
            ? 'bg-[#1a1a1a] border-gray-800'
            : 'bg-white border-gray-200 shadow-sm'
        }`}>
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 rounded-lg bg-amber-500/20">
              <Crown className="w-5 h-5 text-amber-500" />
            </div>
            <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>Premium Users</span>
          </div>
          <p className="text-3xl font-bold">8,234</p>
          <p className="text-sm text-[#1DB954] mt-2">+18% this month</p>
        </div>

        <div className={`p-6 rounded-2xl border ${
          theme === 'dark'
            ? 'bg-[#1a1a1a] border-gray-800'
            : 'bg-white border-gray-200 shadow-sm'
        }`}>
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 rounded-lg bg-green-500/20">
              <DollarSign className="w-5 h-5 text-green-500" />
            </div>
            <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>Monthly Revenue</span>
          </div>
          <p className="text-3xl font-bold">$82,340</p>
          <p className="text-sm text-[#1DB954] mt-2">+23% this month</p>
        </div>

        <div className={`p-6 rounded-2xl border ${
          theme === 'dark'
            ? 'bg-[#1a1a1a] border-gray-800'
            : 'bg-white border-gray-200 shadow-sm'
        }`}>
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 rounded-lg bg-blue-500/20">
              <Lock className="w-5 h-5 text-blue-500" />
            </div>
            <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>Premium Content</span>
          </div>
          <p className="text-3xl font-bold">147</p>
          <p className={`text-sm mt-2 ${theme === 'dark' ? 'text-gray-500' : 'text-gray-600'}`}>items locked</p>
        </div>

        <div className={`p-6 rounded-2xl border ${
          theme === 'dark'
            ? 'bg-[#1a1a1a] border-gray-800'
            : 'bg-white border-gray-200 shadow-sm'
        }`}>
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 rounded-lg bg-purple-500/20">
              <TrendingUp className="w-5 h-5 text-purple-500" />
            </div>
            <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>Conversion Rate</span>
          </div>
          <p className="text-3xl font-bold">17.9%</p>
          <p className="text-sm text-[#1DB954] mt-2">+4.2% this month</p>
        </div>
      </div>

      {/* Premium Configuration */}
      <div className={`p-6 rounded-2xl border ${
        theme === 'dark'
          ? 'bg-[#1a1a1a] border-gray-800'
          : 'bg-white border-gray-200 shadow-sm'
      }`}>
        <h2 className="text-xl font-semibold mb-6">Premium Configuration</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className={`block mb-2 font-medium ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>
              Subscription Price (USD/month)
            </label>
            <input
              type="text"
              value={premiumRules.subscriptionPrice}
              onChange={(e) => setPremiumRules({ ...premiumRules, subscriptionPrice: e.target.value })}
              className={`w-full px-4 py-3 rounded-xl border outline-none transition-all ${
                theme === 'dark'
                  ? 'bg-[#0a0a0a] border-gray-700 focus:border-[#1DB954]'
                  : 'bg-gray-50 border-gray-300 focus:border-[#1DB954]'
              }`}
            />
          </div>

          <div>
            <label className={`block mb-2 font-medium ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>
              Free Trial Period (days)
            </label>
            <input
              type="text"
              value={premiumRules.trialDays}
              onChange={(e) => setPremiumRules({ ...premiumRules, trialDays: e.target.value })}
              className={`w-full px-4 py-3 rounded-xl border outline-none transition-all ${
                theme === 'dark'
                  ? 'bg-[#0a0a0a] border-gray-700 focus:border-[#1DB954]'
                  : 'bg-gray-50 border-gray-300 focus:border-[#1DB954]'
              }`}
            />
          </div>
        </div>

        <div className="mt-6 space-y-4">
          <div className="flex items-center justify-between p-4 rounded-xl bg-gray-800/30">
            <div>
              <p className="font-medium">Auto-lock new content</p>
              <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                Automatically set new uploads as premium
              </p>
            </div>
            <Switch.Root
              checked={premiumRules.autoLockNewContent}
              onCheckedChange={(checked) => setPremiumRules({ ...premiumRules, autoLockNewContent: checked })}
              className={`w-11 h-6 rounded-full relative transition-colors ${
                premiumRules.autoLockNewContent ? 'bg-[#1DB954]' : theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'
              }`}
            >
              <Switch.Thumb className="block w-5 h-5 bg-white rounded-full transition-transform translate-x-0.5 data-[state=checked]:translate-x-[22px]" />
            </Switch.Root>
          </div>

          <div className="flex items-center justify-between p-4 rounded-xl bg-gray-800/30">
            <div>
              <p className="font-medium">Allow subscription gifting</p>
              <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                Let users gift premium subscriptions to others
              </p>
            </div>
            <Switch.Root
              checked={premiumRules.allowGifting}
              onCheckedChange={(checked) => setPremiumRules({ ...premiumRules, allowGifting: checked })}
              className={`w-11 h-6 rounded-full relative transition-colors ${
                premiumRules.allowGifting ? 'bg-[#1DB954]' : theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'
              }`}
            >
              <Switch.Thumb className="block w-5 h-5 bg-white rounded-full transition-transform translate-x-0.5 data-[state=checked]:translate-x-[22px]" />
            </Switch.Root>
          </div>
        </div>

        <button className="mt-6 bg-[#1DB954] hover:bg-[#1ed760] text-white px-6 py-3 rounded-xl font-medium transition-all">
          Save Configuration
        </button>
      </div>

      {/* Premium Content List */}
      <div className={`rounded-2xl border overflow-hidden ${
        theme === 'dark' ? 'bg-[#1a1a1a] border-gray-800' : 'bg-white border-gray-200 shadow-sm'
      }`}>
        <div className="p-6 border-b border-current border-opacity-10">
          <h2 className="text-xl font-semibold">Premium Content</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className={`border-b ${theme === 'dark' ? 'border-gray-800 bg-gray-800/50' : 'border-gray-200 bg-gray-50'}`}>
                <th className="px-6 py-4 text-left font-semibold">Title</th>
                <th className="px-6 py-4 text-left font-semibold">Type</th>
                <th className="px-6 py-4 text-left font-semibold">Subscribers</th>
                <th className="px-6 py-4 text-left font-semibold">Revenue</th>
                <th className="px-6 py-4 text-left font-semibold">Status</th>
                <th className="px-6 py-4 text-left font-semibold">Action</th>
              </tr>
            </thead>
            <tbody>
              {premiumContent.map((content) => (
                <tr
                  key={content.id}
                  className={`border-b transition-colors ${
                    theme === 'dark'
                      ? 'border-gray-800 hover:bg-gray-800/50'
                      : 'border-gray-200 hover:bg-gray-50'
                  }`}
                >
                  <td className="px-6 py-4 font-medium">{content.title}</td>
                  <td className="px-6 py-4">
                    <span className={`px-3 py-1 rounded-full text-sm ${
                      theme === 'dark' ? 'bg-gray-800 text-gray-300' : 'bg-gray-100 text-gray-700'
                    }`}>
                      {content.type}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-gray-500">{content.subscribers.toLocaleString()}</td>
                  <td className="px-6 py-4 font-semibold text-[#1DB954]">{content.revenue}</td>
                  <td className="px-6 py-4">
                    <span className={`flex items-center gap-1 px-3 py-1 rounded-full text-sm w-fit ${
                      content.isLocked
                        ? 'bg-amber-500/20 text-amber-500'
                        : 'bg-gray-500/20 text-gray-500'
                    }`}>
                      {content.isLocked ? <Lock className="w-3 h-3" /> : <Unlock className="w-3 h-3" />}
                      {content.isLocked ? 'Locked' : 'Unlocked'}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <button
                      onClick={() => toggleLock(content.id)}
                      className={`px-4 py-2 rounded-lg font-medium transition-all ${
                        content.isLocked
                          ? theme === 'dark'
                            ? 'bg-gray-800 hover:bg-gray-700'
                            : 'bg-gray-200 hover:bg-gray-300'
                          : 'bg-amber-500/20 hover:bg-amber-500/30 text-amber-500'
                      }`}
                    >
                      {content.isLocked ? 'Unlock' : 'Lock'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
