import React, { useState } from 'react';
import { Plus, Edit, Trash2, Eye, EyeOff, Upload, X, Check } from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';
import * as Dialog from '@radix-ui/react-dialog';
import * as Switch from '@radix-ui/react-switch';

interface AudioTrack {
  id: string;
  cover: string;
  title: string;
  artist: string;
  category: string;
  duration: string;
  visible: boolean;
  published: boolean;
  isPremium: boolean;
}

const mockTracks: AudioTrack[] = [
  { id: '1', cover: '🎙️', title: 'The Prophet\'s Journey', artist: 'Sheikh Ahmad', category: 'Biography', duration: '45:23', visible: true, published: true, isPremium: false },
  { id: '2', cover: '📚', title: 'Stories of Companions', artist: 'Dr. Sarah Khan', category: 'History', duration: '32:15', visible: true, published: true, isPremium: true },
  { id: '3', cover: '🕌', title: 'Islamic History', artist: 'Prof. Hassan', category: 'Education', duration: '58:40', visible: false, published: true, isPremium: false },
  { id: '4', cover: '📖', title: 'Quranic Reflections', artist: 'Imam Abdullah', category: 'Quran', duration: '28:12', visible: true, published: false, isPremium: false },
  { id: '5', cover: '🌙', title: 'Ramadan Special', artist: 'Sheikh Ahmad', category: 'Seasonal', duration: '41:30', visible: true, published: true, isPremium: true },
];

const categories = ['Biography', 'History', 'Education', 'Quran', 'Seasonal', 'Inspiration', 'Stories'];

export function AudioContent() {
  const { theme } = useTheme();
  const [tracks, setTracks] = useState<AudioTrack[]>(mockTracks);
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [uploadForm, setUploadForm] = useState({
    title: '',
    artist: '',
    category: '',
    duration: '',
    isPremium: false,
  });

  const toggleVisibility = (id: string) => {
    setTracks(tracks.map(track =>
      track.id === id ? { ...track, visible: !track.visible } : track
    ));
  };

  const togglePublished = (id: string) => {
    setTracks(tracks.map(track =>
      track.id === id ? { ...track, published: !track.published } : track
    ));
  };

  const deleteTrack = (id: string) => {
    setTracks(tracks.filter(track => track.id !== id));
  };

  const handleUpload = () => {
    // Mock upload functionality
    setIsUploadModalOpen(false);
    setUploadForm({ title: '', artist: '', category: '', duration: '', isPremium: false });
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold mb-2">Audio Content Management</h1>
          <p className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>
            Manage your audio library, metadata, and visibility settings.
          </p>
        </div>
        <Dialog.Root open={isUploadModalOpen} onOpenChange={setIsUploadModalOpen}>
          <Dialog.Trigger asChild>
            <button className="flex items-center gap-2 bg-[#1DB954] hover:bg-[#1ed760] text-white px-6 py-3 rounded-xl font-medium transition-all">
              <Plus className="w-5 h-5" />
              Upload Audio
            </button>
          </Dialog.Trigger>
          <Dialog.Portal>
            <Dialog.Overlay className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40" />
            <Dialog.Content className={`fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-2xl rounded-2xl p-8 z-50 max-h-[90vh] overflow-y-auto ${
              theme === 'dark' ? 'bg-[#1a1a1a] border border-gray-800' : 'bg-white border border-gray-200'
            }`}>
              <div className="flex items-center justify-between mb-6">
                <Dialog.Title className="text-2xl font-bold">Upload New Audio</Dialog.Title>
                <Dialog.Close asChild>
                  <button className={`p-2 rounded-lg transition-all ${
                    theme === 'dark' ? 'hover:bg-gray-800' : 'hover:bg-gray-100'
                  }`}>
                    <X className="w-5 h-5" />
                  </button>
                </Dialog.Close>
              </div>

              <div className="space-y-6">
                {/* File Upload Area */}
                <div className={`border-2 border-dashed rounded-xl p-12 text-center transition-all cursor-pointer ${
                  theme === 'dark'
                    ? 'border-gray-700 hover:border-[#1DB954] hover:bg-gray-800/50'
                    : 'border-gray-300 hover:border-[#1DB954] hover:bg-gray-50'
                }`}>
                  <Upload className="w-12 h-12 mx-auto mb-4 text-gray-500" />
                  <p className="font-medium mb-2">Drag & drop audio file here</p>
                  <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                    or click to browse (MP3, WAV, M4A)
                  </p>
                </div>

                {/* Cover Image Upload */}
                <div>
                  <label className={`block mb-2 font-medium ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>
                    Cover Image
                  </label>
                  <div className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
                    theme === 'dark'
                      ? 'border-gray-700 hover:border-[#1DB954] hover:bg-gray-800/50'
                      : 'border-gray-300 hover:border-[#1DB954] hover:bg-gray-50'
                  }`}>
                    <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                      Upload cover image (JPG, PNG)
                    </p>
                  </div>
                </div>

                {/* Track Title */}
                <div>
                  <label className={`block mb-2 font-medium ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>
                    Track Title *
                  </label>
                  <input
                    type="text"
                    value={uploadForm.title}
                    onChange={(e) => setUploadForm({ ...uploadForm, title: e.target.value })}
                    placeholder="Enter track title"
                    className={`w-full px-4 py-3 rounded-xl border outline-none transition-all ${
                      theme === 'dark'
                        ? 'bg-[#0a0a0a] border-gray-700 focus:border-[#1DB954]'
                        : 'bg-gray-50 border-gray-300 focus:border-[#1DB954]'
                    }`}
                  />
                </div>

                {/* Artist Name */}
                <div>
                  <label className={`block mb-2 font-medium ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>
                    Artist Name *
                  </label>
                  <input
                    type="text"
                    value={uploadForm.artist}
                    onChange={(e) => setUploadForm({ ...uploadForm, artist: e.target.value })}
                    placeholder="Enter artist name"
                    className={`w-full px-4 py-3 rounded-xl border outline-none transition-all ${
                      theme === 'dark'
                        ? 'bg-[#0a0a0a] border-gray-700 focus:border-[#1DB954]'
                        : 'bg-gray-50 border-gray-300 focus:border-[#1DB954]'
                    }`}
                  />
                </div>

                {/* Category */}
                <div>
                  <label className={`block mb-2 font-medium ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>
                    Category *
                  </label>
                  <select
                    value={uploadForm.category}
                    onChange={(e) => setUploadForm({ ...uploadForm, category: e.target.value })}
                    className={`w-full px-4 py-3 rounded-xl border outline-none transition-all ${
                      theme === 'dark'
                        ? 'bg-[#0a0a0a] border-gray-700 focus:border-[#1DB954]'
                        : 'bg-gray-50 border-gray-300 focus:border-[#1DB954]'
                    }`}
                  >
                    <option value="">Select category</option>
                    {categories.map(cat => (
                      <option key={cat} value={cat}>{cat}</option>
                    ))}
                  </select>
                </div>

                {/* Premium Toggle */}
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium">Premium Content</p>
                    <p className={`text-sm ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                      Restrict access to premium subscribers only
                    </p>
                  </div>
                  <Switch.Root
                    checked={uploadForm.isPremium}
                    onCheckedChange={(checked) => setUploadForm({ ...uploadForm, isPremium: checked })}
                    className={`w-11 h-6 rounded-full relative transition-colors ${
                      uploadForm.isPremium ? 'bg-[#1DB954]' : theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'
                    }`}
                  >
                    <Switch.Thumb className="block w-5 h-5 bg-white rounded-full transition-transform translate-x-0.5 data-[state=checked]:translate-x-[22px]" />
                  </Switch.Root>
                </div>

                {/* Action Buttons */}
                <div className="flex gap-3 pt-4">
                  <button
                    onClick={handleUpload}
                    className="flex-1 bg-[#1DB954] hover:bg-[#1ed760] text-white py-3 rounded-xl font-medium transition-all"
                  >
                    Upload Track
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

      {/* Tracks Table */}
      <div className={`rounded-2xl border overflow-hidden ${
        theme === 'dark' ? 'bg-[#1a1a1a] border-gray-800' : 'bg-white border-gray-200 shadow-sm'
      }`}>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className={`border-b ${theme === 'dark' ? 'border-gray-800 bg-gray-800/50' : 'border-gray-200 bg-gray-50'}`}>
                <th className="px-6 py-4 text-left font-semibold">Cover</th>
                <th className="px-6 py-4 text-left font-semibold">Track Title</th>
                <th className="px-6 py-4 text-left font-semibold">Artist</th>
                <th className="px-6 py-4 text-left font-semibold">Category</th>
                <th className="px-6 py-4 text-left font-semibold">Duration</th>
                <th className="px-6 py-4 text-left font-semibold">Status</th>
                <th className="px-6 py-4 text-left font-semibold">Visibility</th>
                <th className="px-6 py-4 text-left font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody>
              {tracks.map((track) => (
                <tr
                  key={track.id}
                  className={`border-b transition-colors ${
                    theme === 'dark'
                      ? 'border-gray-800 hover:bg-gray-800/50'
                      : 'border-gray-200 hover:bg-gray-50'
                  }`}
                >
                  <td className="px-6 py-4">
                    <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-[#1DB954] to-[#1ed760] flex items-center justify-center text-2xl">
                      {track.cover}
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div>
                      <p className="font-medium">{track.title}</p>
                      {track.isPremium && (
                        <span className="inline-flex items-center gap-1 text-xs bg-amber-500/20 text-amber-500 px-2 py-0.5 rounded-full mt-1">
                          Premium
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4">{track.artist}</td>
                  <td className="px-6 py-4">
                    <span className={`px-3 py-1 rounded-full text-sm ${
                      theme === 'dark' ? 'bg-gray-800 text-gray-300' : 'bg-gray-100 text-gray-700'
                    }`}>
                      {track.category}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-gray-500">{track.duration}</td>
                  <td className="px-6 py-4">
                    <button
                      onClick={() => togglePublished(track.id)}
                      className={`flex items-center gap-1 px-3 py-1 rounded-full text-sm transition-all ${
                        track.published
                          ? 'bg-[#1DB954]/20 text-[#1DB954]'
                          : 'bg-orange-500/20 text-orange-500'
                      }`}
                    >
                      {track.published ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                      {track.published ? 'Published' : 'Draft'}
                    </button>
                  </td>
                  <td className="px-6 py-4">
                    <button
                      onClick={() => toggleVisibility(track.id)}
                      className={`p-2 rounded-lg transition-all ${
                        theme === 'dark' ? 'hover:bg-gray-700' : 'hover:bg-gray-200'
                      }`}
                    >
                      {track.visible ? (
                        <Eye className="w-5 h-5 text-[#1DB954]" />
                      ) : (
                        <EyeOff className="w-5 h-5 text-gray-500" />
                      )}
                    </button>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <button className={`p-2 rounded-lg transition-all ${
                        theme === 'dark' ? 'hover:bg-gray-700' : 'hover:bg-gray-200'
                      }`}>
                        <Edit className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => deleteTrack(track.id)}
                        className="p-2 rounded-lg hover:bg-red-500/10 text-red-500 transition-all"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
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
