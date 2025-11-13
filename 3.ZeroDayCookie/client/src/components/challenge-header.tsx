import { Shield, Terminal } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface ChallengeHeaderProps {
  difficulty: string;
  description: string;
}

export function ChallengeHeader({ difficulty, description }: ChallengeHeaderProps) {
  return (
    <div className="relative border-b-2 border-primary/30 pb-8">
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary/10 border border-primary/30 rounded-md">
              <Terminal className="h-6 w-6 text-primary" data-testid="icon-terminal" />
            </div>
            <h1
              className="text-4xl sm:text-5xl font-bold font-mono tracking-tight text-primary uppercase"
              data-testid="text-challenge-title"
            >
              Lỗ Hổng JWT
            </h1>
          </div>
          <p
            className="text-muted-foreground font-mono text-sm sm:text-base max-w-3xl"
            data-testid="text-challenge-description"
          >
            {description}
          </p>
        </div>
        
        <Badge
          variant="outline"
          className="bg-destructive/10 text-destructive border-destructive/30 px-4 py-2 text-sm font-mono uppercase tracking-wider"
          data-testid="badge-difficulty"
        >
          <Shield className="h-4 w-4 mr-2" />
          {difficulty}
        </Badge>
      </div>

      <div className="mt-6 flex items-center gap-2 text-xs font-mono text-muted-foreground">
        <span className="inline-block w-2 h-2 bg-primary rounded-full animate-pulse" />
        <span data-testid="text-status">THỬ THÁCH ĐANG HOẠT ĐỘNG</span>
      </div>
    </div>
  );
}
