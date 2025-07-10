
'use client';

import { Button } from '@/components/ui/button';
import { Plus, Settings, LogOut, User } from 'lucide-react';
import { useSession, signOut } from 'next-auth/react';
import { useState } from 'react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

interface HeaderProps {
  onNewAppointment: () => void;
  onOpenSettings: () => void;
}

export function Header({ onNewAppointment, onOpenSettings }: HeaderProps) {
  const { data: session } = useSession();

  const handleSignOut = async () => {
    await signOut({ callbackUrl: '/auth/signin' });
  };

  return (
    <header className="sticky top-0 z-50 bg-white/80 backdrop-blur-xl border-b border-white/30 shadow-sm">
      <div className="container mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Logo */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-amber-400 to-yellow-600 rounded-xl flex items-center justify-center shadow-lg">
              <img 
                src="/images/justice-scales-logo.png" 
                alt="Roberson Law Justice Scales" 
                className="w-6 h-6 object-contain filter brightness-110"
              />
            </div>
            <div>
              <h1 className="text-2xl font-bold">
                <span className="bg-gradient-to-r from-slate-900 via-blue-900 to-slate-900 bg-clip-text text-transparent">
                  Roberson Law
                </span>{' '}
                <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-emerald-600 bg-clip-text text-transparent">
                  Calendar
                </span>
              </h1>
            </div>
          </div>

          {/* Center CTA */}
          <Button
            onClick={onNewAppointment}
            className="bg-gradient-to-r from-blue-500 via-blue-600 to-blue-700 hover:from-blue-600 hover:via-blue-700 hover:to-blue-800 text-white shadow-xl hover:shadow-2xl transform hover:-translate-y-1 transition-all duration-300 px-8 py-6 text-lg font-semibold"
          >
            <Plus className="h-5 w-5 mr-2" />
            New Appointment
          </Button>

          {/* User Menu */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" className="flex items-center gap-2 hover:bg-slate-50">
                <User className="h-4 w-4" />
                <span className="hidden sm:inline">
                  {session?.user?.name || 'User'}
                </span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <DropdownMenuItem onClick={onOpenSettings}>
                <Settings className="h-4 w-4 mr-2" />
                Settings
              </DropdownMenuItem>
              <DropdownMenuItem onClick={handleSignOut}>
                <LogOut className="h-4 w-4 mr-2" />
                Sign Out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
}
