import { Shield, Zap, Target } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { ThemeToggle } from "@/components/theme-toggle";

export function ChallengeHeader() {
  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60" data-testid="header-challenge">
      <div className="container flex h-16 items-center justify-between gap-4 px-6">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-md bg-primary/10" data-testid="icon-header-shield">
            <Shield className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight" data-testid="text-header-title">Thử Thách CTF</h1>
            <p className="text-xs text-muted-foreground" data-testid="text-header-subtitle">DOM XSS trong 302 Redirect</p>
          </div>
        </div>
        
        <div className="flex items-center gap-3">
          <Badge variant="outline" className="gap-1.5" data-testid="badge-difficulty">
            <Target className="w-3 h-3" />
            Cấp Độ Chuyên Gia
          </Badge>
          <Badge variant="outline" className="gap-1.5" data-testid="badge-category">
            <Zap className="w-3 h-3" />
            Bảo Mật Web
          </Badge>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
