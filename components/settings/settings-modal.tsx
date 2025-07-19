
'use client';

import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Switch } from '@/components/ui/switch';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Settings, Users, Link, Bell, Plus, Edit, Trash2, Mail, Smartphone } from 'lucide-react';
import { toast } from 'sonner';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  staff: any[];
  onStaffUpdate: () => void;
}

export function SettingsModal({
  isOpen,
  onClose,
  staff,
  onStaffUpdate,
}: SettingsModalProps) {
  const [activeTab, setActiveTab] = useState('staff');
  const [newStaff, setNewStaff] = useState({
    name: '',
    email: '',
    phone: '',
    position: '',
    department: '',
    color: '#3b82f6',
  });
  const [isAddingStaff, setIsAddingStaff] = useState(false);
  const [notifications, setNotifications] = useState({
    emailEnabled: true,
    emailConfirmation: true,
    emailReminder: true,
    emailReminderMinutes: 60,
    smsEnabled: false,
    smsConfirmation: false,
    smsReminder: false,
    smsReminderMinutes: 30,
  });

  const staffColors = [
    '#10b981', '#3b82f6', '#8b5cf6', '#f59e0b', '#ef4444', '#06b6d4',
    '#84cc16', '#f97316', '#ec4899', '#6366f1', '#14b8a6', '#f59e0b'
  ];

  const handleAddStaff = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsAddingStaff(true);
    
    try {
      const response = await fetch('/api/staff', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newStaff),
      });

      if (response.ok) {
        toast.success('Staff member added successfully');
        setNewStaff({
          name: '',
          email: '',
          phone: '',
          position: '',
          department: '',
          color: '#3b82f6',
        });
        onStaffUpdate();
      } else {
        toast.error('Failed to add staff member');
      }
    } catch (error) {
      console.error('Error adding staff:', error);
      toast.error('Failed to add staff member');
    } finally {
      setIsAddingStaff(false);
    }
  };

  const handleDeleteStaff = async (staffId: string) => {
    if (!window.confirm('Are you sure you want to delete this staff member?')) return;

    try {
      const response = await fetch(`/api/staff/${staffId}`, {
        method: 'DELETE',
      });

      if (response.ok) {
        toast.success('Staff member deleted successfully');
        onStaffUpdate();
      } else {
        toast.error('Failed to delete staff member');
      }
    } catch (error) {
      console.error('Error deleting staff:', error);
      toast.error('Failed to delete staff member');
    }
  };

  const handleConnectGoogle = () => {
    window.open('/api/auth/google', '_blank');
    toast.info('Google Calendar integration initiated');
  };

  const handleConnectOutlook = () => {
    window.open('/api/auth/outlook', '_blank');
    toast.info('Outlook Calendar integration initiated');
  };

  const handleSaveNotifications = async () => {
    try {
      const response = await fetch('/api/notifications/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(notifications),
      });

      if (response.ok) {
        toast.success('Notification settings saved');
      } else {
        toast.error('Failed to save notification settings');
      }
    } catch (error) {
      console.error('Error saving notifications:', error);
      toast.error('Failed to save notification settings');
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-2xl">
            <Settings className="h-6 w-6 text-blue-600" />
            Settings
          </DialogTitle>
        </DialogHeader>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="staff" className="flex items-center gap-2">
              <Users className="h-4 w-4" />
              Staff
            </TabsTrigger>
            <TabsTrigger value="integrations" className="flex items-center gap-2">
              <Link className="h-4 w-4" />
              Integrations
            </TabsTrigger>
            <TabsTrigger value="notifications" className="flex items-center gap-2">
              <Bell className="h-4 w-4" />
              Notifications
            </TabsTrigger>
          </TabsList>

          <TabsContent value="staff" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Plus className="h-5 w-5" />
                  Add New Staff Member
                </CardTitle>
                <CardDescription>
                  Add a new staff member to the calendar system
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleAddStaff} className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="name">Full Name *</Label>
                      <Input
                        id="name"
                        value={newStaff.name}
                        onChange={(e) => setNewStaff({ ...newStaff, name: e.target.value })}
                        placeholder="John Doe"
                        required
                      />
                    </div>
                    <div>
                      <Label htmlFor="email">Email *</Label>
                      <Input
                        id="email"
                        type="email"
                        value={newStaff.email}
                        onChange={(e) => setNewStaff({ ...newStaff, email: e.target.value })}
                        placeholder="john@example.com"
                        required
                      />
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                      <Label htmlFor="phone">Phone</Label>
                      <Input
                        id="phone"
                        value={newStaff.phone}
                        onChange={(e) => setNewStaff({ ...newStaff, phone: e.target.value })}
                        placeholder="(555) 123-4567"
                      />
                    </div>
                    <div>
                      <Label htmlFor="position">Position</Label>
                      <Input
                        id="position"
                        value={newStaff.position}
                        onChange={(e) => setNewStaff({ ...newStaff, position: e.target.value })}
                        placeholder="Attorney"
                      />
                    </div>
                    <div>
                      <Label htmlFor="department">Department</Label>
                      <Input
                        id="department"
                        value={newStaff.department}
                        onChange={(e) => setNewStaff({ ...newStaff, department: e.target.value })}
                        placeholder="Roberson Law"
                      />
                    </div>
                  </div>
                  
                  <div>
                    <Label>Calendar Color</Label>
                    <div className="flex gap-2 mt-2">
                      {staffColors.map((color) => (
                        <button
                          key={color}
                          type="button"
                          className={`w-8 h-8 rounded-full border-2 ${
                            newStaff.color === color ? 'border-slate-400' : 'border-transparent'
                          }`}
                          style={{ backgroundColor: color }}
                          onClick={() => setNewStaff({ ...newStaff, color })}
                        />
                      ))}
                    </div>
                  </div>
                  
                  <Button type="submit" disabled={isAddingStaff}>
                    <Plus className="h-4 w-4 mr-2" />
                    {isAddingStaff ? 'Adding...' : 'Add Staff Member'}
                  </Button>
                </form>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Current Staff Members</CardTitle>
                <CardDescription>
                  Manage existing staff members
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {staff?.map((member) => (
                    <div key={member.id} className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex items-center gap-3">
                        <div 
                          className="w-6 h-6 rounded-full" 
                          style={{ backgroundColor: member.color }}
                        />
                        <div>
                          <p className="font-medium">{member.name}</p>
                          <p className="text-sm text-muted-foreground">{member.email}</p>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <Button variant="outline" size="sm">
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button 
                          variant="destructive" 
                          size="sm"
                          onClick={() => handleDeleteStaff(member.id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="integrations" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Calendar Integrations</CardTitle>
                <CardDescription>
                  Connect your external calendar services for seamless synchronization
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between p-4 border rounded-lg">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                      <span className="text-blue-600 font-bold">G</span>
                    </div>
                    <div>
                      <h4 className="font-medium">Google Calendar</h4>
                      <p className="text-sm text-muted-foreground">Sync with Google Calendar</p>
                    </div>
                  </div>
                  <Button onClick={handleConnectGoogle}>
                    Connect
                  </Button>
                </div>

                <div className="flex items-center justify-between p-4 border rounded-lg">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-orange-100 rounded-lg flex items-center justify-center">
                      <span className="text-orange-600 font-bold">O</span>
                    </div>
                    <div>
                      <h4 className="font-medium">Outlook Calendar</h4>
                      <p className="text-sm text-muted-foreground">Sync with Microsoft Outlook</p>
                    </div>
                  </div>
                  <Button onClick={handleConnectOutlook}>
                    Connect
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="notifications" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Mail className="h-5 w-5" />
                  Email Notifications
                </CardTitle>
                <CardDescription>
                  Configure email notification preferences
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium">Enable Email Notifications</p>
                    <p className="text-sm text-muted-foreground">Receive notifications via email</p>
                  </div>
                  <Switch
                    checked={notifications.emailEnabled}
                    onCheckedChange={(checked) => 
                      setNotifications({ ...notifications, emailEnabled: checked })
                    }
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium">Appointment Confirmations</p>
                    <p className="text-sm text-muted-foreground">Email when appointments are created</p>
                  </div>
                  <Switch
                    checked={notifications.emailConfirmation}
                    onCheckedChange={(checked) => 
                      setNotifications({ ...notifications, emailConfirmation: checked })
                    }
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium">Appointment Reminders</p>
                    <p className="text-sm text-muted-foreground">Email reminders before appointments</p>
                  </div>
                  <Switch
                    checked={notifications.emailReminder}
                    onCheckedChange={(checked) => 
                      setNotifications({ ...notifications, emailReminder: checked })
                    }
                  />
                </div>

                <div>
                  <Label>Reminder Time (minutes before)</Label>
                  <Select 
                    value={notifications.emailReminderMinutes.toString()} 
                    onValueChange={(value) => 
                      setNotifications({ ...notifications, emailReminderMinutes: parseInt(value) })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="15">15 minutes</SelectItem>
                      <SelectItem value="30">30 minutes</SelectItem>
                      <SelectItem value="60">1 hour</SelectItem>
                      <SelectItem value="120">2 hours</SelectItem>
                      <SelectItem value="1440">1 day</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Smartphone className="h-5 w-5" />
                  SMS Notifications
                </CardTitle>
                <CardDescription>
                  Configure SMS notification preferences
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium">Enable SMS Notifications</p>
                    <p className="text-sm text-muted-foreground">Receive notifications via SMS</p>
                  </div>
                  <Switch
                    checked={notifications.smsEnabled}
                    onCheckedChange={(checked) => 
                      setNotifications({ ...notifications, smsEnabled: checked })
                    }
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium">Appointment Confirmations</p>
                    <p className="text-sm text-muted-foreground">SMS when appointments are created</p>
                  </div>
                  <Switch
                    checked={notifications.smsConfirmation}
                    onCheckedChange={(checked) => 
                      setNotifications({ ...notifications, smsConfirmation: checked })
                    }
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium">Appointment Reminders</p>
                    <p className="text-sm text-muted-foreground">SMS reminders before appointments</p>
                  </div>
                  <Switch
                    checked={notifications.smsReminder}
                    onCheckedChange={(checked) => 
                      setNotifications({ ...notifications, smsReminder: checked })
                    }
                  />
                </div>

                <div>
                  <Label>Reminder Time (minutes before)</Label>
                  <Select 
                    value={notifications.smsReminderMinutes.toString()} 
                    onValueChange={(value) => 
                      setNotifications({ ...notifications, smsReminderMinutes: parseInt(value) })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="15">15 minutes</SelectItem>
                      <SelectItem value="30">30 minutes</SelectItem>
                      <SelectItem value="60">1 hour</SelectItem>
                      <SelectItem value="120">2 hours</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </CardContent>
            </Card>

            <div className="flex justify-end">
              <Button onClick={handleSaveNotifications}>
                Save Notification Settings
              </Button>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
