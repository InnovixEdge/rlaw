// app/layout.tsx
export const metadata = {
  title: 'Roberson Law Scheduler',
  description: 'Scheduling Solutions',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
