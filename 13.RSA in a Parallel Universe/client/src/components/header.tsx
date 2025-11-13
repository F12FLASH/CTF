import { ThemeToggle } from "./theme-toggle";
import { Badge } from "@/components/ui/badge";
import { Shield, Trophy } from "lucide-react";

export function Header() {
  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur-md supports-[backdrop-filter]:bg-background/60 shadow-sm">
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="relative">
            <Shield className="w-8 h-8 text-primary" />
            <Trophy className="w-4 h-4 text-primary absolute -bottom-1 -right-1" />
          </div>
          <div className="flex items-center gap-3">
            <div>
              <h1 className="text-lg font-bold tracking-tight" data-testid="header-title">
                RSA in a Parallel Universe
              </h1>
              <div className="flex items-center gap-2 mt-0.5">
                <Badge variant="secondary" className="text-xs px-2 py-0" data-testid="badge-challenge-type">
                  CTF Challenge
                </Badge>
                <Badge variant="destructive" className="text-xs px-2 py-0" data-testid="badge-difficulty">
                  Master
                </Badge>
              </div>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="hidden md:flex items-center gap-2 text-xs text-muted-foreground" data-testid="status-indicator">
            <span className="w-2 h-2 bg-green-500 rounded-full"></span>
            <span>Online</span>
          </div>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
