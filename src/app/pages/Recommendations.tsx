import React, { useState } from 'react';
import { Sparkles, ChevronUp, ChevronDown, TrendingUp, Clock, Folder } from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';
import * as Switch from '@radix-ui/react-switch';

interface RecommendationRule {
  id: string;
  name: string;
  type: 'category' | 'top-played' | 'recent';
  isActive: boolean;
  priority: number;
  description: string;
  icon: React.ReactNode;
}

const mockRules: RecommendationRule[] = [
  {
    id: '1',
    name: 'Top Played This Week',
    type: 'top-played',
    isActive: true,
    priority: 1,
    description: 'Show most played tracks from the last 7 days',
    icon: <TrendingUp className="w-5 h-5" />,
  },
  {
    id: '2',
    name: 'Recently Added',
    type: 'recent',
    isActive: true,
    priority: 2,
    description: 'Display newly uploaded content',
    icon: <Clock className="w-5 h-5" />,
  },
  {
    id: '3',
    name: 'Category Based',
    type: 'category',
    isActive: true,
    priority: 3,
    description: 'Recommend based on user listening history',
    icon: <Folder className="w-5 h-5" />,
  },
];

export function Recommendations() {
  const { theme } = useTheme();
  const [rules, setRules] = useState<RecommendationRule[]>(mockRules);

  const toggleRule = (id: string) => {
    setRules(rules.map(rule =>
      rule.id === id ? { ...rule, isActive: !rule.isActive } : rule
    ));
  };

  const movePriority = (id: string, direction: 'up' | 'down') => {
    const index = rules.findIndex(r => r.id === id);
    if (
      (direction === 'up' && index === 0) ||
      (direction === 'down' && index === rules.length - 1)
    ) {
      return;
    }

    const newRules = [...rules];
    const targetIndex = direction === 'up' ? index - 1 : index + 1;
    [newRules[index], newRules[targetIndex]] = [newRules[targetIndex], newRules[index]];
    
    // Update priorities
    newRules.forEach((rule, idx) => {
      rule.priority = idx + 1;
    });

    setRules(newRules);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold mb-2">Recommendation Engine</h1>
        <p className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>
          Configure and manage content recommendation rules and algorithms.
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className={`p-6 rounded-2xl border ${
          theme === 'dark'
            ? 'bg-[#1a1a1a] border-gray-800'
            : 'bg-white border-gray-200 shadow-sm'
        }`}>
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 rounded-lg bg-green-500/20">
              <Sparkles className="w-5 h-5 text-green-500" />
            </div>
            <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>Active Rules</span>
          </div>
          <p className="text-3xl font-bold">{rules.filter(r => r.isActive).length}</p>
        </div>

        <div className={`p-6 rounded-2xl border ${
          theme === 'dark'
            ? 'bg-[#1a1a1a] border-gray-800'
            : 'bg-white border-gray-200 shadow-sm'
        }`}>
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 rounded-lg bg-blue-500/20">
              <TrendingUp className="w-5 h-5 text-blue-500" />
            </div>
            <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>Click-through Rate</span>
          </div>
          <p className="text-3xl font-bold">24.6%</p>
        </div>

        <div className={`p-6 rounded-2xl border ${
          theme === 'dark'
            ? 'bg-[#1a1a1a] border-gray-800'
            : 'bg-white border-gray-200 shadow-sm'
        }`}>
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 rounded-lg bg-purple-500/20">
              <Clock className="w-5 h-5 text-purple-500" />
            </div>
            <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>Avg. Listen Time</span>
          </div>
          <p className="text-3xl font-bold">18m</p>
        </div>
      </div>

      {/* Recommendation Rules */}
      <div className={`rounded-2xl border overflow-hidden ${
        theme === 'dark' ? 'bg-[#1a1a1a] border-gray-800' : 'bg-white border-gray-200 shadow-sm'
      }`}>
        <div className="p-6 border-b border-current border-opacity-10">
          <h2 className="text-xl font-semibold">Recommendation Rules</h2>
          <p className={`text-sm mt-1 ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
            Rules are applied in priority order. Drag to reorder.
          </p>
        </div>

        <div className="divide-y divide-current divide-opacity-10">
          {rules.map((rule, index) => (
            <div
              key={rule.id}
              className={`p-6 transition-colors ${
                theme === 'dark' ? 'hover:bg-gray-800/50' : 'hover:bg-gray-50'
              }`}
            >
              <div className="flex items-start gap-4">
                {/* Priority Badge */}
                <div className={`flex-shrink-0 w-12 h-12 rounded-xl flex items-center justify-center font-bold ${
                  rule.isActive
                    ? 'bg-[#1DB954]/20 text-[#1DB954]'
                    : theme === 'dark'
                    ? 'bg-gray-800 text-gray-500'
                    : 'bg-gray-100 text-gray-400'
                }`}>
                  {rule.priority}
                </div>

                {/* Rule Icon */}
                <div className={`flex-shrink-0 p-3 rounded-xl ${
                  rule.isActive
                    ? 'bg-blue-500/20 text-blue-500'
                    : theme === 'dark'
                    ? 'bg-gray-800 text-gray-500'
                    : 'bg-gray-100 text-gray-400'
                }`}>
                  {rule.icon}
                </div>

                {/* Rule Details */}
                <div className="flex-1 min-w-0">
                  <h3 className="font-semibold text-lg mb-1">{rule.name}</h3>
                  <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                    {rule.description}
                  </p>
                  <span className={`inline-block mt-2 px-3 py-1 rounded-full text-xs ${
                    theme === 'dark' ? 'bg-gray-800 text-gray-400' : 'bg-gray-100 text-gray-600'
                  }`}>
                    {rule.type}
                  </span>
                </div>

                {/* Controls */}
                <div className="flex items-center gap-3">
                  {/* Priority Controls */}
                  <div className="flex flex-col gap-1">
                    <button
                      onClick={() => movePriority(rule.id, 'up')}
                      disabled={index === 0}
                      className={`p-1 rounded transition-all ${
                        index === 0
                          ? 'opacity-30 cursor-not-allowed'
                          : theme === 'dark'
                          ? 'hover:bg-gray-700'
                          : 'hover:bg-gray-200'
                      }`}
                    >
                      <ChevronUp className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => movePriority(rule.id, 'down')}
                      disabled={index === rules.length - 1}
                      className={`p-1 rounded transition-all ${
                        index === rules.length - 1
                          ? 'opacity-30 cursor-not-allowed'
                          : theme === 'dark'
                          ? 'hover:bg-gray-700'
                          : 'hover:bg-gray-200'
                      }`}
                    >
                      <ChevronDown className="w-4 h-4" />
                    </button>
                  </div>

                  {/* Active Toggle */}
                  <Switch.Root
                    checked={rule.isActive}
                    onCheckedChange={() => toggleRule(rule.id)}
                    className={`w-11 h-6 rounded-full relative transition-colors ${
                      rule.isActive ? 'bg-[#1DB954]' : theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'
                    }`}
                  >
                    <Switch.Thumb className="block w-5 h-5 bg-white rounded-full transition-transform translate-x-0.5 data-[state=checked]:translate-x-[22px]" />
                  </Switch.Root>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Preview Section */}
      <div className={`p-6 rounded-2xl border ${
        theme === 'dark'
          ? 'bg-[#1a1a1a] border-gray-800'
          : 'bg-white border-gray-200 shadow-sm'
      }`}>
        <h2 className="text-xl font-semibold mb-4">Recommendation Preview</h2>
        <p className={`mb-6 ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
          Preview how recommendations will appear to users based on current rules.
        </p>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className={`p-4 rounded-xl border transition-all ${
                theme === 'dark'
                  ? 'bg-gray-800/50 border-gray-700 hover:border-[#1DB954]'
                  : 'bg-gray-50 border-gray-200 hover:border-[#1DB954]'
              }`}
            >
              <div className="w-full aspect-square bg-gradient-to-br from-[#1DB954] to-[#1ed760] rounded-lg mb-3 flex items-center justify-center text-3xl">
                🎙️
              </div>
              <p className="font-medium mb-1">Recommended Track {i}</p>
              <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                Based on: {rules.find(r => r.isActive && r.priority === i)?.name || 'N/A'}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
