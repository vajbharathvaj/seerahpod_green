import React, { useState } from 'react';
import { Globe, Lock, Bell, Palette, Database, Key } from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';
import * as Switch from '@radix-ui/react-switch';
import * as Tabs from '@radix-ui/react-tabs';

export function Settings() {
  const { theme, toggleTheme } = useTheme();
  const [platformSettings, setPlatformSettings] = useState({
    platformVisible: true,
    allowPublicSignup: true,
    maintenanceMode: false,
    emailNotifications: true,
    pushNotifications: false,
  });

  const [accessSettings, setAccessSettings] = useState({
    requireEmailVerification: true,
    allowGuestAccess: false,
    contentModeration: true,
  });

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold mb-2">Settings</h1>
        <p className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>
          Configure platform settings, preferences, and integrations.
        </p>
      </div>

      {/* Settings Tabs */}
      <Tabs.Root defaultValue="general" className={`rounded-2xl border overflow-hidden ${
        theme === 'dark' ? 'bg-[#1a1a1a] border-gray-800' : 'bg-white border-gray-200 shadow-sm'
      }`}>
        <Tabs.List className={`flex border-b ${
          theme === 'dark' ? 'border-gray-800' : 'border-gray-200'
        }`}>
          <Tabs.Trigger
            value="general"
            className={`flex-1 px-6 py-4 font-medium transition-all border-b-2 border-transparent ${
              theme === 'dark'
                ? 'text-gray-400 hover:text-white data-[state=active]:text-white data-[state=active]:border-[#1DB954]'
                : 'text-gray-600 hover:text-gray-900 data-[state=active]:text-gray-900 data-[state=active]:border-[#1DB954]'
            }`}
          >
            General
          </Tabs.Trigger>
          <Tabs.Trigger
            value="access"
            className={`flex-1 px-6 py-4 font-medium transition-all border-b-2 border-transparent ${
              theme === 'dark'
                ? 'text-gray-400 hover:text-white data-[state=active]:text-white data-[state=active]:border-[#1DB954]'
                : 'text-gray-600 hover:text-gray-900 data-[state=active]:text-gray-900 data-[state=active]:border-[#1DB954]'
            }`}
          >
            Access Control
          </Tabs.Trigger>
          <Tabs.Trigger
            value="integrations"
            className={`flex-1 px-6 py-4 font-medium transition-all border-b-2 border-transparent ${
              theme === 'dark'
                ? 'text-gray-400 hover:text-white data-[state=active]:text-white data-[state=active]:border-[#1DB954]'
                : 'text-gray-600 hover:text-gray-900 data-[state=active]:text-gray-900 data-[state=active]:border-[#1DB954]'
            }`}
          >
            Integrations
          </Tabs.Trigger>
          <Tabs.Trigger
            value="appearance"
            className={`flex-1 px-6 py-4 font-medium transition-all border-b-2 border-transparent ${
              theme === 'dark'
                ? 'text-gray-400 hover:text-white data-[state=active]:text-white data-[state=active]:border-[#1DB954]'
                : 'text-gray-600 hover:text-gray-900 data-[state=active]:text-gray-900 data-[state=active]:border-[#1DB954]'
            }`}
          >
            Appearance
          </Tabs.Trigger>
        </Tabs.List>

        {/* General Settings */}
        <Tabs.Content value="general" className="p-6">
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Globe className="w-5 h-5" />
                Platform Visibility
              </h3>
              <div className="space-y-4">
                <div className={`flex items-center justify-between p-4 rounded-xl ${
                  theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-50'
                }`}>
                  <div>
                    <p className="font-medium">Platform Visible</p>
                    <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                      Make the platform publicly accessible
                    </p>
                  </div>
                  <Switch.Root
                    checked={platformSettings.platformVisible}
                    onCheckedChange={(checked) => setPlatformSettings({ ...platformSettings, platformVisible: checked })}
                    className={`w-11 h-6 rounded-full relative transition-colors ${
                      platformSettings.platformVisible ? 'bg-[#1DB954]' : theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'
                    }`}
                  >
                    <Switch.Thumb className="block w-5 h-5 bg-white rounded-full transition-transform translate-x-0.5 data-[state=checked]:translate-x-[22px]" />
                  </Switch.Root>
                </div>

                <div className={`flex items-center justify-between p-4 rounded-xl ${
                  theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-50'
                }`}>
                  <div>
                    <p className="font-medium">Allow Public Signup</p>
                    <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                      Let new users register for accounts
                    </p>
                  </div>
                  <Switch.Root
                    checked={platformSettings.allowPublicSignup}
                    onCheckedChange={(checked) => setPlatformSettings({ ...platformSettings, allowPublicSignup: checked })}
                    className={`w-11 h-6 rounded-full relative transition-colors ${
                      platformSettings.allowPublicSignup ? 'bg-[#1DB954]' : theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'
                    }`}
                  >
                    <Switch.Thumb className="block w-5 h-5 bg-white rounded-full transition-transform translate-x-0.5 data-[state=checked]:translate-x-[22px]" />
                  </Switch.Root>
                </div>

                <div className={`flex items-center justify-between p-4 rounded-xl ${
                  theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-50'
                }`}>
                  <div>
                    <p className="font-medium">Maintenance Mode</p>
                    <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                      Temporarily disable platform access
                    </p>
                  </div>
                  <Switch.Root
                    checked={platformSettings.maintenanceMode}
                    onCheckedChange={(checked) => setPlatformSettings({ ...platformSettings, maintenanceMode: checked })}
                    className={`w-11 h-6 rounded-full relative transition-colors ${
                      platformSettings.maintenanceMode ? 'bg-[#1DB954]' : theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'
                    }`}
                  >
                    <Switch.Thumb className="block w-5 h-5 bg-white rounded-full transition-transform translate-x-0.5 data-[state=checked]:translate-x-[22px]" />
                  </Switch.Root>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Bell className="w-5 h-5" />
                Notifications
              </h3>
              <div className="space-y-4">
                <div className={`flex items-center justify-between p-4 rounded-xl ${
                  theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-50'
                }`}>
                  <div>
                    <p className="font-medium">Email Notifications</p>
                    <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                      Send email alerts for important events
                    </p>
                  </div>
                  <Switch.Root
                    checked={platformSettings.emailNotifications}
                    onCheckedChange={(checked) => setPlatformSettings({ ...platformSettings, emailNotifications: checked })}
                    className={`w-11 h-6 rounded-full relative transition-colors ${
                      platformSettings.emailNotifications ? 'bg-[#1DB954]' : theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'
                    }`}
                  >
                    <Switch.Thumb className="block w-5 h-5 bg-white rounded-full transition-transform translate-x-0.5 data-[state=checked]:translate-x-[22px]" />
                  </Switch.Root>
                </div>

                <div className={`flex items-center justify-between p-4 rounded-xl ${
                  theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-50'
                }`}>
                  <div>
                    <p className="font-medium">Push Notifications</p>
                    <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                      Enable browser push notifications
                    </p>
                  </div>
                  <Switch.Root
                    checked={platformSettings.pushNotifications}
                    onCheckedChange={(checked) => setPlatformSettings({ ...platformSettings, pushNotifications: checked })}
                    className={`w-11 h-6 rounded-full relative transition-colors ${
                      platformSettings.pushNotifications ? 'bg-[#1DB954]' : theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'
                    }`}
                  >
                    <Switch.Thumb className="block w-5 h-5 bg-white rounded-full transition-transform translate-x-0.5 data-[state=checked]:translate-x-[22px]" />
                  </Switch.Root>
                </div>
              </div>
            </div>
          </div>
        </Tabs.Content>

        {/* Access Control */}
        <Tabs.Content value="access" className="p-6">
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Lock className="w-5 h-5" />
                Content Access Rules
              </h3>
              <div className="space-y-4">
                <div className={`flex items-center justify-between p-4 rounded-xl ${
                  theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-50'
                }`}>
                  <div>
                    <p className="font-medium">Require Email Verification</p>
                    <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                      Users must verify email before accessing content
                    </p>
                  </div>
                  <Switch.Root
                    checked={accessSettings.requireEmailVerification}
                    onCheckedChange={(checked) => setAccessSettings({ ...accessSettings, requireEmailVerification: checked })}
                    className={`w-11 h-6 rounded-full relative transition-colors ${
                      accessSettings.requireEmailVerification ? 'bg-[#1DB954]' : theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'
                    }`}
                  >
                    <Switch.Thumb className="block w-5 h-5 bg-white rounded-full transition-transform translate-x-0.5 data-[state=checked]:translate-x-[22px]" />
                  </Switch.Root>
                </div>

                <div className={`flex items-center justify-between p-4 rounded-xl ${
                  theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-50'
                }`}>
                  <div>
                    <p className="font-medium">Allow Guest Access</p>
                    <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                      Let users browse without creating an account
                    </p>
                  </div>
                  <Switch.Root
                    checked={accessSettings.allowGuestAccess}
                    onCheckedChange={(checked) => setAccessSettings({ ...accessSettings, allowGuestAccess: checked })}
                    className={`w-11 h-6 rounded-full relative transition-colors ${
                      accessSettings.allowGuestAccess ? 'bg-[#1DB954]' : theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'
                    }`}
                  >
                    <Switch.Thumb className="block w-5 h-5 bg-white rounded-full transition-transform translate-x-0.5 data-[state=checked]:translate-x-[22px]" />
                  </Switch.Root>
                </div>

                <div className={`flex items-center justify-between p-4 rounded-xl ${
                  theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-50'
                }`}>
                  <div>
                    <p className="font-medium">Content Moderation</p>
                    <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                      Require admin approval before publishing
                    </p>
                  </div>
                  <Switch.Root
                    checked={accessSettings.contentModeration}
                    onCheckedChange={(checked) => setAccessSettings({ ...accessSettings, contentModeration: checked })}
                    className={`w-11 h-6 rounded-full relative transition-colors ${
                      accessSettings.contentModeration ? 'bg-[#1DB954]' : theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'
                    }`}
                  >
                    <Switch.Thumb className="block w-5 h-5 bg-white rounded-full transition-transform translate-x-0.5 data-[state=checked]:translate-x-[22px]" />
                  </Switch.Root>
                </div>
              </div>
            </div>
          </div>
        </Tabs.Content>

        {/* Integrations */}
        <Tabs.Content value="integrations" className="p-6">
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Key className="w-5 h-5" />
                Third-Party Integrations
              </h3>
              
              <div className="space-y-4">
                {/* Google Login */}
                <div className={`p-6 rounded-xl border ${
                  theme === 'dark' ? 'bg-gray-800/50 border-gray-700' : 'bg-gray-50 border-gray-200'
                }`}>
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className="w-12 h-12 rounded-lg bg-white flex items-center justify-center">
                        <span className="text-2xl">G</span>
                      </div>
                      <div>
                        <h4 className="font-semibold">Google Authentication</h4>
                        <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                          OAuth 2.0 integration
                        </p>
                      </div>
                    </div>
                    <span className="px-3 py-1 rounded-full text-sm bg-[#1DB954]/20 text-[#1DB954]">
                      Connected
                    </span>
                  </div>
                  <div className="space-y-2">
                    <div>
                      <label className={`block text-sm font-medium mb-1 ${
                        theme === 'dark' ? 'text-gray-400' : 'text-gray-600'
                      }`}>
                        Client ID
                      </label>
                      <input
                        type="text"
                        value="••••••••••••••••••••"
                        readOnly
                        className={`w-full px-3 py-2 rounded-lg border text-sm ${
                          theme === 'dark'
                            ? 'bg-[#0a0a0a] border-gray-700'
                            : 'bg-white border-gray-300'
                        }`}
                      />
                    </div>
                    <button className={`text-sm px-4 py-2 rounded-lg transition-all ${
                      theme === 'dark'
                        ? 'bg-gray-700 hover:bg-gray-600'
                        : 'bg-gray-200 hover:bg-gray-300'
                    }`}>
                      Reconfigure
                    </button>
                  </div>
                </div>

                {/* Storage Provider */}
                <div className={`p-6 rounded-xl border ${
                  theme === 'dark' ? 'bg-gray-800/50 border-gray-700' : 'bg-gray-50 border-gray-200'
                }`}>
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className="w-12 h-12 rounded-lg bg-blue-500/20 flex items-center justify-center">
                        <Database className="w-6 h-6 text-blue-500" />
                      </div>
                      <div>
                        <h4 className="font-semibold">Cloud Storage</h4>
                        <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                          Audio file storage provider
                        </p>
                      </div>
                    </div>
                    <span className={`px-3 py-1 rounded-full text-sm ${
                      theme === 'dark' ? 'bg-gray-700 text-gray-400' : 'bg-gray-200 text-gray-600'
                    }`}>
                      Not configured
                    </span>
                  </div>
                  <button className="bg-[#1DB954] hover:bg-[#1ed760] text-white px-4 py-2 rounded-lg text-sm transition-all">
                    Configure Storage
                  </button>
                </div>
              </div>
            </div>
          </div>
        </Tabs.Content>

        {/* Appearance */}
        <Tabs.Content value="appearance" className="p-6">
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Palette className="w-5 h-5" />
                Theme & Display
              </h3>
              
              <div className={`p-6 rounded-xl ${
                theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-50'
              }`}>
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <p className="font-medium">Dark Mode</p>
                    <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                      Toggle between light and dark themes
                    </p>
                  </div>
                  <Switch.Root
                    checked={theme === 'dark'}
                    onCheckedChange={toggleTheme}
                    className={`w-11 h-6 rounded-full relative transition-colors ${
                      theme === 'dark' ? 'bg-[#1DB954]' : 'bg-gray-300'
                    }`}
                  >
                    <Switch.Thumb className="block w-5 h-5 bg-white rounded-full transition-transform translate-x-0.5 data-[state=checked]:translate-x-[22px]" />
                  </Switch.Root>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                    theme === 'light'
                      ? 'border-[#1DB954] bg-white'
                      : 'border-gray-600 bg-gray-700'
                  }`}>
                    <div className="w-full h-20 bg-white rounded mb-2 border border-gray-200"></div>
                    <p className="text-sm font-medium text-center">Light Mode</p>
                  </div>
                  <div className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                    theme === 'dark'
                      ? 'border-[#1DB954] bg-[#1a1a1a]'
                      : 'border-gray-300 bg-gray-100'
                  }`}>
                    <div className="w-full h-20 bg-[#0a0a0a] rounded mb-2 border border-gray-800"></div>
                    <p className="text-sm font-medium text-center">Dark Mode</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </Tabs.Content>
      </Tabs.Root>

      {/* Save Button */}
      <div className="flex justify-end">
        <button className="bg-[#1DB954] hover:bg-[#1ed760] text-white px-8 py-3 rounded-xl font-medium transition-all">
          Save All Changes
        </button>
      </div>
    </div>
  );
}
