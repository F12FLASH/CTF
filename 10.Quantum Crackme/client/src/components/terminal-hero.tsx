import { Download, ChevronDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useState, useEffect } from "react";

export function TerminalHero() {
  const [typedText, setTypedText] = useState("");
  const fullText = "CPU-Specific Execution | QEMU Emulation | Master Level";

  useEffect(() => {
    let currentIndex = 0;
    const interval = setInterval(() => {
      if (currentIndex <= fullText.length) {
        setTypedText(fullText.substring(0, currentIndex));
        currentIndex++;
      } else {
        clearInterval(interval);
      }
    }, 50);

    return () => clearInterval(interval);
  }, []);

  const scrollToChallenge = () => {
    document.getElementById("challenge-overview")?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <section className="relative min-h-[90vh] flex items-center justify-center overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-b from-background via-background/95 to-background" />
      
      <div className="relative z-10 max-w-5xl mx-auto px-6 py-20 text-center">
        <div className="mb-8 inline-block">
          <div className="flex items-center gap-2 mb-4 justify-center">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-destructive" data-testid="terminal-dot-red" />
              <div className="w-3 h-3 rounded-full bg-chart-4" data-testid="terminal-dot-yellow" />
              <div className="w-3 h-3 rounded-full bg-primary" data-testid="terminal-dot-green" />
            </div>
          </div>
          
          <Badge 
            variant="outline" 
            className="mb-6 px-4 py-2 text-xs uppercase tracking-wider font-mono border-primary/30 bg-primary/5"
            data-testid="badge-category"
          >
            Reverse Engineering CTF
          </Badge>
        </div>

        <h1 
          className="font-display text-5xl md:text-6xl lg:text-7xl font-bold mb-6 tracking-tight"
          data-testid="text-hero-title"
        >
          Quantum <span className="text-primary">Crackme</span>
        </h1>

        <div className="flex items-center justify-center gap-1 mb-8" data-testid="difficulty-stars">
          {[1, 2, 3, 4, 5].map((star) => (
            <span key={star} className="text-3xl text-primary">⭐</span>
          ))}
        </div>

        <div className="min-h-[2rem] mb-12">
          <p 
            className="font-mono text-base lg:text-lg text-muted-foreground"
            data-testid="text-subtitle"
          >
            {typedText}
            <span className="animate-pulse">_</span>
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <Button 
            size="lg" 
            className="gap-2 uppercase tracking-wider font-mono text-sm px-8 shadow-lg shadow-primary/20 hover:shadow-primary/40 transition-all"
            onClick={() => window.location.href = '/api/download/binary'}
            data-testid="button-download-binary"
          >
            <Download className="w-5 h-5" />
            Tải Binary
          </Button>
          
          <Button 
            size="lg" 
            variant="outline" 
            onClick={scrollToChallenge}
            className="gap-2 uppercase tracking-wider font-mono text-sm px-8 border-primary/30 hover:bg-primary/10"
            data-testid="button-view-challenge"
          >
            Xem Thử Thách
          </Button>
        </div>

        <div className="absolute bottom-8 left-1/2 -translate-x-1/2 animate-bounce">
          <ChevronDown className="w-6 h-6 text-muted-foreground" />
        </div>
      </div>

      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_120%,rgba(34,197,94,0.1),transparent_50%)] pointer-events-none" />
    </section>
  );
}
