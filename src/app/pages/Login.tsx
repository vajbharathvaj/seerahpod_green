import React, { useState } from 'react';
import { useNavigate } from 'react-router';
import { Mail, Lock, Chrome, Eye, EyeOff } from 'lucide-react';
import { motion } from 'motion/react';
import { useTheme } from '../contexts/ThemeContext';

export function Login() {
  const navigate = useNavigate();
  const { theme } = useTheme();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    navigate('/');
  };

  const handleGoogleLogin = () => {
    navigate('/');
  };

  return (
    <div className={`min-h-screen flex items-center justify-center relative overflow-hidden ${
      theme === 'dark' 
        ? 'bg-gradient-to-br from-[#0a0a0a] via-[#121212] to-[#0a0a0a]' 
        : 'bg-gradient-to-br from-gray-50 via-white to-gray-100'
    }`}>
      {/* Background decorative elements */}
      <div className="absolute inset-0 overflow-hidden">
        <motion.div
          className="absolute top-1/4 -left-20 w-96 h-96 bg-[#1DB954]/10 rounded-full blur-3xl"
          animate={{
            scale: [1, 1.2, 1],
            opacity: [0.3, 0.5, 0.3],
          }}
          transition={{
            duration: 8,
            repeat: Infinity,
            ease: "easeInOut"
          }}
        />
        <motion.div
          className="absolute bottom-1/4 -right-20 w-96 h-96 bg-[#1DB954]/10 rounded-full blur-3xl"
          animate={{
            scale: [1.2, 1, 1.2],
            opacity: [0.5, 0.3, 0.5],
          }}
          transition={{
            duration: 8,
            repeat: Infinity,
            ease: "easeInOut"
          }}
        />
      </div>

      {/* Login Card */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="relative z-10 w-full max-w-md mx-4"
      >
        {/* Logo and Tagline */}
        <div className="text-center mb-8">
          <motion.h1
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2, duration: 0.6 }}
            className="text-5xl font-bold text-white mb-3"
          >
            seerahPod
          </motion.h1>
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.4, duration: 0.6 }}
            className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}
          >
            Admin Console for Audio Excellence
          </motion.p>
        </div>

        {/* Login Form Card */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.3, duration: 0.6 }}
          className={`rounded-2xl p-8 shadow-2xl backdrop-blur-sm ${
            theme === 'dark'
              ? 'bg-[#1a1a1a]/90 border border-gray-800'
              : 'bg-white/90 border border-gray-200'
          }`}
        >
          {/* Google Login */}
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={handleGoogleLogin}
            className={`w-full flex items-center justify-center gap-3 px-6 py-3.5 rounded-xl font-medium transition-all mb-6 ${
              theme === 'dark'
                ? 'bg-white text-gray-900 hover:bg-gray-100'
                : 'bg-gray-900 text-white hover:bg-gray-800'
            }`}
          >
            <Chrome className="w-5 h-5" />
            Continue with Google
          </motion.button>

          {/* Divider */}
          <div className="relative my-6">
            <div className={`absolute inset-0 flex items-center ${
              theme === 'dark' ? 'opacity-20' : 'opacity-30'
            }`}>
              <div className="w-full border-t border-current" />
            </div>
            <div className="relative flex justify-center text-sm">
              <span className={`px-4 ${
                theme === 'dark' ? 'bg-[#1a1a1a] text-gray-500' : 'bg-white text-gray-600'
              }`}>
                Or continue with email
              </span>
            </div>
          </div>

          {/* Email/Password Form */}
          <form onSubmit={handleLogin} className="space-y-4">
            {/* Email Input */}
            <div>
              <label className={`block text-sm font-medium mb-2 ${
                theme === 'dark' ? 'text-gray-300' : 'text-gray-700'
              }`}>
                Email Address
              </label>
              <div className="relative">
                <Mail className={`absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 ${
                  theme === 'dark' ? 'text-gray-500' : 'text-gray-400'
                }`} />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="admin@seerahpod.com"
                  className={`w-full pl-12 pr-4 py-3 rounded-xl border transition-all outline-none ${
                    theme === 'dark'
                      ? 'bg-[#0a0a0a] border-gray-700 text-white placeholder-gray-600 focus:border-[#1DB954] focus:ring-2 focus:ring-[#1DB954]/20'
                      : 'bg-gray-50 border-gray-300 text-gray-900 placeholder-gray-400 focus:border-[#1DB954] focus:ring-2 focus:ring-[#1DB954]/20'
                  }`}
                  required
                />
              </div>
            </div>

            {/* Password Input */}
            <div>
              <label className={`block text-sm font-medium mb-2 ${
                theme === 'dark' ? 'text-gray-300' : 'text-gray-700'
              }`}>
                Password
              </label>
              <div className="relative">
                <Lock className={`absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 ${
                  theme === 'dark' ? 'text-gray-500' : 'text-gray-400'
                }`} />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className={`w-full pl-12 pr-12 py-3 rounded-xl border transition-all outline-none ${
                    theme === 'dark'
                      ? 'bg-[#0a0a0a] border-gray-700 text-white placeholder-gray-600 focus:border-[#1DB954] focus:ring-2 focus:ring-[#1DB954]/20'
                      : 'bg-gray-50 border-gray-300 text-gray-900 placeholder-gray-400 focus:border-[#1DB954] focus:ring-2 focus:ring-[#1DB954]/20'
                  }`}
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className={`absolute right-4 top-1/2 -translate-y-1/2 ${
                    theme === 'dark' ? 'text-gray-500 hover:text-gray-400' : 'text-gray-400 hover:text-gray-600'
                  }`}
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {/* Submit Button */}
            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              type="submit"
              className="w-full bg-[#1DB954] hover:bg-[#1ed760] text-white font-semibold py-3.5 rounded-xl shadow-lg shadow-[#1DB954]/30 transition-all mt-6"
            >
              Sign In to Dashboard
            </motion.button>
          </form>

          {/* Secure Access Caption */}
          <p className={`text-center text-sm mt-6 ${
            theme === 'dark' ? 'text-gray-500' : 'text-gray-600'
          }`}>
            🔒 Secure Admin Access
          </p>
        </motion.div>
      </motion.div>
    </div>
  );
}
