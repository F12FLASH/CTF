import { Terminal, Flag } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface HeaderProps {
  onOpenFlagModal: () => void;
}

export function Header({ onOpenFlagModal }: HeaderProps) {
  return (
    <header className="fixed top-0 left-0 right-0 z-50 border-b border-border bg-background/95 backdrop-blur-sm">
      <div className="container mx-auto px-4 h-16 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <Terminal className="w-6 h-6 text-primary" data-testid="icon-terminal" />
          <h1 className="text-xl font-bold bg-gradient-to-r from-primary via-secondary to-primary bg-clip-text text-transparent">
            GraphQL Apocalypse
          </h1>
          <Badge variant="destructive" className="text-xs" data-testid="badge-difficulty">
            CỰC KHÓ
          </Badge>
        </div>
        
        <Button 
          onClick={onOpenFlagModal}
          className="gap-2"
          data-testid="button-submit-flag"
        >
          <Flag className="w-4 h-4" />
          Nộp Flag
        </Button>
      </div>
    </header>
  );
}
