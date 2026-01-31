import './globals.css';
export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-dvh min-w-full">
        {children}
      </body>
    </html>
  );
}
