
'use client';

import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { useState } from 'react';
import { Users, Filter, Download, Zap, ChevronLeft, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';

interface SidebarProps {
  staff: any[];
  selectedStaff: string[];
  onStaffSelectionChange: (staffIds: string[]) => void;
  onBulkCreate: () => void;
  onExportCalendar: () => void;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
}

export function Sidebar({
  staff,
  selectedStaff,
  onStaffSelectionChange,
  onBulkCreate,
  onExportCalendar,
  isCollapsed,
  onToggleCollapse,
}: SidebarProps) {
  const handleStaffToggle = (staffId: string) => {
    const newSelection = selectedStaff.includes(staffId)
      ? selectedStaff.filter(id => id !== staffId)
      : [...selectedStaff, staffId];
    onStaffSelectionChange(newSelection);
  };

  const handleSelectAll = () => {
    const allStaffIds = staff?.map(s => s.id) || [];
    onStaffSelectionChange(selectedStaff.length === allStaffIds.length ? [] : allStaffIds);
  };

  if (isCollapsed) {
    return (
      <div className="w-16 bg-white/80 backdrop-blur-xl border-r border-white/30 p-4 flex flex-col">
        <Button
          variant="ghost"
          size="icon"
          onClick={onToggleCollapse}
          className="hover:bg-slate-100 mb-4"
        >
          <ChevronRight className="h-4 w-4" />
        </Button>
        
        <div className="space-y-2">
          <Button variant="ghost" size="icon" className="hover:bg-slate-100">
            <Users className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" className="hover:bg-slate-100">
            <Zap className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" className="hover:bg-slate-100">
            <Download className="h-4 w-4" />
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="w-80 bg-white/80 backdrop-blur-xl border-r border-white/30 p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-semibold text-slate-800">Filters & Actions</h2>
        <Button
          variant="ghost"
          size="icon"
          onClick={onToggleCollapse}
          className="hover:bg-slate-100"
        >
          <ChevronLeft className="h-4 w-4" />
        </Button>
      </div>
      
      {/* Staff Filter Section */}
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-4">
          <Users className="h-5 w-5 text-blue-600" />
          <h3 className="font-semibold text-slate-700">Staff Members</h3>
        </div>
        
        <div className="space-y-3">
          <div className="flex items-center gap-2 p-2 rounded-lg border border-slate-200">
            <Checkbox
              id="select-all"
              checked={selectedStaff.length === staff?.length}
              onCheckedChange={handleSelectAll}
            />
            <label htmlFor="select-all" className="text-sm font-medium text-slate-700">
              Select All ({staff?.length || 0})
            </label>
          </div>
          
          {staff?.map((member) => (
            <div
              key={member.id}
              className="staff-filter-item"
              onClick={() => handleStaffToggle(member.id)}
            >
              <Checkbox
                id={member.id}
                checked={selectedStaff.includes(member.id)}
                onCheckedChange={() => handleStaffToggle(member.id)}
              />
              <div
                className="staff-color-dot"
                style={{ backgroundColor: member.color }}
              />
              <label
                htmlFor={member.id}
                className="flex-1 text-sm font-medium text-slate-700 cursor-pointer"
              >
                {member.name}
              </label>
            </div>
          ))}
        </div>
      </div>
      
      {/* Quick Actions */}
      <div className="space-y-3">
        <h3 className="font-semibold text-slate-700 mb-3">Quick Actions</h3>
        
        <Button
          onClick={onBulkCreate}
          className="w-full bg-gradient-to-r from-purple-500 to-purple-600 hover:from-purple-600 hover:to-purple-700 text-white shadow-lg hover:shadow-xl transition-all duration-300"
        >
          <Zap className="h-4 w-4 mr-2" />
          Bulk Create Slots
        </Button>
        
        <Button
          onClick={onExportCalendar}
          variant="outline"
          className="w-full hover:bg-slate-50 border-slate-300"
        >
          <Download className="h-4 w-4 mr-2" />
          Export Calendar
        </Button>
      </div>
      
      {/* Sync Status */}
      <div className="mt-8 p-4 bg-gradient-to-r from-emerald-50 to-emerald-100 rounded-lg border border-emerald-200">
        <h3 className="font-semibold text-emerald-800 mb-2">Sync Status</h3>
        <div className="space-y-2 text-sm">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-emerald-500 rounded-full"></div>
            <span className="text-emerald-700">Google Calendar: Connected</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
            <span className="text-yellow-700">Outlook: Pending</span>
          </div>
        </div>
      </div>
    </div>
  );
}
