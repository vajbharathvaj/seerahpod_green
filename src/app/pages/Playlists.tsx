import React, { useState } from 'react';
import { Plus, Edit, Trash2, Lock, Globe, Eye } from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';
import * as Dialog from '@radix-ui/react-dialog';

interface Playlist {
  id: string;
  name: string;
  cover: string;
  trackCount: number;
  visibility: 'public' | 'private' | 'premium';
}

const mockPlaylists: Playlist[] = [
  { id: '1', name: 'Top Seerah Stories', cover: '🎙️', trackCount: 24, visibility: 'public' },
  { id: '2', name: 'Ramadan Collection', cover: '🌙', trackCount: 18, visibility: 'premium' },
  { id: '3', name: 'Daily Inspirations', cover: '✨', trackCount: 32, visibility: 'public' },
  { id: '4', name: 'Islamic History', cover: '📚', trackCount: 15, visibility: 'public' },
  { id: '5', name: 'Premium Series', cover: '👑', trackCount: 12, visibility: 'premium' },
  { id: '6', name: 'Children Stories', cover: '🧸', trackCount: 20, visibility: 'public' },
];

export function Playlists() {
  const { theme } = useTheme();
  const [playlists, setPlaylists] = useState<Playlist[]>(mockPlaylists);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);

  const getVisibilityBadge = (visibility: string) => {
    switch (visibility) {
      case 'public':
        return (
          <span className="flex items-center gap-1 px-3 py-1 rounded-full text-xs bg-[#1DB954]/20 text-[#1DB954]">
            <Globe className="w-3 h-3" />
            Public
          </span>
        );
      case 'private':
        return (
          <span className="flex items-center gap-1 px-3 py-1 rounded-full text-xs bg-gray-500/20 text-gray-500">
            <Eye className="w-3 h-3" />
            Private
          </span>
        );
      case 'premium':
        return (
          <span className="flex items-center gap-1 px-3 py-1 rounded-full text-xs bg-amber-500/20 text-amber-500">
            <Lock className="w-3 h-3" />
            Premium
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold mb-2">Playlist Management</h1>
          <p className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>
            Organize your audio content into curated playlists.
          </p>
        </div>
        <button
          onClick={() => setIsCreateModalOpen(true)}
          className="flex items-center gap-2 bg-[#1DB954] hover:bg-[#1ed760] text-white px-6 py-3 rounded-xl font-medium transition-all"
        >
          <Plus className="w-5 h-5" />
          Create Playlist
        </button>
      </div>

      {/* Playlists Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {playlists.map((playlist) => (
          <div
            key={playlist.id}
            className={`group rounded-2xl border overflow-hidden transition-all hover:scale-105 cursor-pointer ${
              theme === 'dark'
                ? 'bg-[#1a1a1a] border-gray-800 hover:border-gray-700'
                : 'bg-white border-gray-200 hover:border-gray-300 shadow-sm'
            }`}
          >
            {/* Playlist Cover */}
            <div className="aspect-square bg-gradient-to-br from-[#1DB954] to-[#1ed760] flex items-center justify-center text-6xl relative overflow-hidden">
              {playlist.cover}
              <div className="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center gap-2">
                <button className="p-3 bg-white/20 backdrop-blur-sm rounded-full hover:bg-white/30 transition-all">
                  <Edit className="w-5 h-5 text-white" />
                </button>
                <button className="p-3 bg-white/20 backdrop-blur-sm rounded-full hover:bg-red-500/80 transition-all">
                  <Trash2 className="w-5 h-5 text-white" />
                </button>
              </div>
            </div>

            {/* Playlist Info */}
            <div className="p-5">
              <h3 className="font-semibold text-lg mb-2">{playlist.name}</h3>
              <div className="flex items-center justify-between">
                <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                  {playlist.trackCount} tracks
                </p>
                {getVisibilityBadge(playlist.visibility)}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Create Playlist Modal */}
      <Dialog.Root open={isCreateModalOpen} onOpenChange={setIsCreateModalOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40" />
          <Dialog.Content className={`fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-lg rounded-2xl p-8 z-50 ${
            theme === 'dark' ? 'bg-[#1a1a1a] border border-gray-800' : 'bg-white border border-gray-200'
          }`}>
            <Dialog.Title className="text-2xl font-bold mb-6">Create New Playlist</Dialog.Title>
            
            <div className="space-y-4">
              <div>
                <label className={`block mb-2 font-medium ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>
                  Playlist Name
                </label>
                <input
                  type="text"
                  placeholder="Enter playlist name"
                  className={`w-full px-4 py-3 rounded-xl border outline-none transition-all ${
                    theme === 'dark'
                      ? 'bg-[#0a0a0a] border-gray-700 focus:border-[#1DB954]'
                      : 'bg-gray-50 border-gray-300 focus:border-[#1DB954]'
                  }`}
                />
              </div>

              <div>
                <label className={`block mb-2 font-medium ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>
                  Visibility
                </label>
                <select className={`w-full px-4 py-3 rounded-xl border outline-none transition-all ${
                  theme === 'dark'
                    ? 'bg-[#0a0a0a] border-gray-700 focus:border-[#1DB954]'
                    : 'bg-gray-50 border-gray-300 focus:border-[#1DB954]'
                }`}>
                  <option value="public">Public</option>
                  <option value="private">Private</option>
                  <option value="premium">Premium Only</option>
                </select>
              </div>

              <div className="flex gap-3 pt-4">
                <button className="flex-1 bg-[#1DB954] hover:bg-[#1ed760] text-white py-3 rounded-xl font-medium transition-all">
                  Create Playlist
                </button>
                <Dialog.Close asChild>
                  <button className={`flex-1 py-3 rounded-xl font-medium transition-all ${
                    theme === 'dark'
                      ? 'bg-gray-800 hover:bg-gray-700'
                      : 'bg-gray-200 hover:bg-gray-300'
                  }`}>
                    Cancel
                  </button>
                </Dialog.Close>
              </div>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
