'use client';

/**
 * Settings Page - Two column layout
 */

import { useState } from 'react';
import { useUser } from '@clerk/nextjs';
import { ChevronRight, Search } from 'lucide-react';

type SettingsSection =
  | 'account'
  | 'privacy'
  | 'notifications'
  | 'resources'
  | 'accessibility'
  | 'help';

export default function SettingsPage() {
  const { user } = useUser();
  const [activeSection, setActiveSection] = useState<SettingsSection>('account');

  const menuItems: { key: SettingsSection; label: string }[] = [
    { key: 'account', label: 'Your account' },
    { key: 'privacy', label: 'Privacy and safety' },
    { key: 'notifications', label: 'Notification' },
    { key: 'resources', label: 'Additional resources' },
    { key: 'accessibility', label: 'Accessibility, display and languages' },
    { key: 'help', label: 'Help  Center' },
  ];

  const accountDetails = [
    {
      label: 'Username',
      value: user?.username || '@stv0r',
    },
    {
      label: 'Phone',
      value: '+000000000',
    },
    {
      label: 'Email',
      value: user?.primaryEmailAddress?.emailAddress || 'example@gmail.com',
    },
    {
      label: 'Country',
      value: 'Choose',
    },
    {
      label: 'Account creation',
      value: 'Jul 22, 2021, 4:59:34 AM\n178.90.253.54 (Malaysia)',
    },
    {
      label: 'Gender',
      value: 'Male',
    },
    {
      label: 'Date of Birth',
      value: '10.08.2000',
    },
  ];

  return (
    <div className="flex h-screen">
      {/* Left Sidebar - Settings Menu */}
      <div className="w-96 border-r border-gray-800 flex flex-col">
        {/* Header */}
        <div className="p-4 border-b border-gray-800">
          <h1 className="text-2xl font-bold mb-4">Settings</h1>

          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search"
              className="w-full bg-gray-900 border border-gray-800 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-green-500 transition"
            />
          </div>
        </div>

        {/* Menu */}
        <nav className="flex-1 overflow-y-auto py-2">
          {menuItems.map((item) => (
            <button
              key={item.key}
              onClick={() => setActiveSection(item.key)}
              className={`w-full px-6 py-4 flex items-center justify-between hover:bg-gray-900 transition ${
                activeSection === item.key ? 'bg-gray-900 border-r-2 border-green-500' : ''
              }`}
            >
              <span className="font-medium">{item.label}</span>
              <ChevronRight className="w-5 h-5 text-gray-500" />
            </button>
          ))}
        </nav>
      </div>

      {/* Right Content - Settings Details */}
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-3xl mx-auto p-8">
          {/* Account Section */}
          {activeSection === 'account' && (
            <div>
              <h2 className="text-2xl font-bold mb-2">Your Account</h2>
              <p className="text-gray-400 mb-8">
                See information about your account, download an archive of your data, or learn about your account deactivation options
              </p>

              <div className="space-y-4">
                {accountDetails.map((detail, index) => (
                  <button
                    key={index}
                    className="w-full flex items-center justify-between p-4 bg-gray-900/50 hover:bg-gray-900 rounded-lg transition group"
                  >
                    <div className="flex-1 text-left">
                      <div className="text-sm text-gray-400 mb-1">{detail.label}</div>
                      <div className="font-medium whitespace-pre-line">{detail.value}</div>
                    </div>
                    <ChevronRight className="w-5 h-5 text-gray-500 group-hover:text-white transition" />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Privacy Section */}
          {activeSection === 'privacy' && (
            <div>
              <h2 className="text-2xl font-bold mb-2">Privacy and safety</h2>
              <p className="text-gray-400 mb-8">
                Manage what information you see and share on Stvor
              </p>

              <div className="text-center py-12 text-gray-500">
                <div className="text-6xl mb-4">🔒</div>
                <h3 className="text-xl font-semibold mb-2">Privacy Settings</h3>
                <p className="text-sm">This section is under development</p>
              </div>
            </div>
          )}

          {/* Notifications Section */}
          {activeSection === 'notifications' && (
            <div>
              <h2 className="text-2xl font-bold mb-2">Notification</h2>
              <p className="text-gray-400 mb-8">
                Select the kinds of notifications you get about your activities and recommendations
              </p>

              <div className="text-center py-12 text-gray-500">
                <div className="text-6xl mb-4">🔔</div>
                <h3 className="text-xl font-semibold mb-2">Notification Settings</h3>
                <p className="text-sm">This section is under development</p>
              </div>
            </div>
          )}

          {/* Resources Section */}
          {activeSection === 'resources' && (
            <div>
              <h2 className="text-2xl font-bold mb-2">Additional resources</h2>
              <p className="text-gray-400 mb-8">
                Check out other resources for helpful tools and information
              </p>

              <div className="text-center py-12 text-gray-500">
                <div className="text-6xl mb-4">📚</div>
                <h3 className="text-xl font-semibold mb-2">Additional Resources</h3>
                <p className="text-sm">This section is under development</p>
              </div>
            </div>
          )}

          {/* Accessibility Section */}
          {activeSection === 'accessibility' && (
            <div>
              <h2 className="text-2xl font-bold mb-2">Accessibility, display and languages</h2>
              <p className="text-gray-400 mb-8">
                Manage how Stvor content is displayed to you
              </p>

              <div className="text-center py-12 text-gray-500">
                <div className="text-6xl mb-4">♿</div>
                <h3 className="text-xl font-semibold mb-2">Accessibility Settings</h3>
                <p className="text-sm">This section is under development</p>
              </div>
            </div>
          )}

          {/* Help Center Section */}
          {activeSection === 'help' && (
            <div>
              <h2 className="text-2xl font-bold mb-2">Help  Center</h2>
              <p className="text-gray-400 mb-8">
                Get help using Stvor and find answers to frequently asked questions
              </p>

              <div className="text-center py-12 text-gray-500">
                <div className="text-6xl mb-4">❓</div>
                <h3 className="text-xl font-semibold mb-2">Help Center</h3>
                <p className="text-sm">This section is under development</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
