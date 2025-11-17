import { Shield } from "lucide-react";
import { ThemeToggle } from "./theme-toggle";

export function Header() {
  return (
    <header className="sticky top-0 z-50 h-16 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container mx-auto h-full px-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="h-6 w-6 text-primary" />
          <div>
            <h1 className="font-display text-lg font-semibold leading-none">
              Báo Thù OTP
            </h1>
            <p className="text-xs text-muted-foreground">
              Thử Thách CTF Mật Mã
            </p>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          <div className="hidden sm:flex items-center gap-2">
            <span className="text-xs uppercase tracking-wider text-muted-foreground">
              Độ khó
            </span>
            <div className="flex gap-0.5">
              {[...Array(1)].map((_, i) => (
                <span key={i} className="text-yellow-500">⭐</span>
              ))}
            </div>
          </div>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
