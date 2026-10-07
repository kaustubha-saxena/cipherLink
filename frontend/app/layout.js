import "./globals.css";

export const metadata = {
  title: "CipherLink - Secure. Temporary. Private.",
  description: "Create a temporary CipherLink room or join with a room code.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
