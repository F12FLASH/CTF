import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/theme-toggle";
import { Download, Flag, Wrench, BookOpen, Target } from "lucide-react";

export function Navigation() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToSection = (id: string) => {
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <nav 
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled 
          ? "bg-background/95 backdrop-blur-md border-b border-border shadow-lg" 
          : "bg-transparent"
      }`}
      data-testid="navigation"
    >
      <div className="max-w-7xl mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Target className="w-6 h-6 text-primary" />
            <span className="font-display font-bold text-xl">
              Quantum <span className="text-primary">CTF</span>
            </span>
          </div>

          <div className="hidden md:flex items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => scrollToSection("challenge-overview")}
              className="font-mono text-xs uppercase tracking-wider"
              data-testid="nav-link-challenge"
            >
              <BookOpen className="w-4 h-4 mr-1" />
              Challenge
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => scrollToSection("solution-methods")}
              className="font-mono text-xs uppercase tracking-wider"
              data-testid="nav-link-solutions"
            >
              <Wrench className="w-4 h-4 mr-1" />
              Solutions
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => scrollToSection("flag-submission")}
              className="font-mono text-xs uppercase tracking-wider"
              data-testid="nav-link-submit"
            >
              <Flag className="w-4 h-4 mr-1" />
              Submit
            </Button>
          </div>

          <div className="flex items-center gap-2">
            <Button
              size="sm"
              className="gap-2 font-mono text-xs uppercase tracking-wider hidden sm:flex"
              onClick={() => window.location.href = '/api/download/binary'}
              data-testid="nav-button-download"
            >
              <Download className="w-4 h-4" />
              Binary
            </Button>
            <ThemeToggle />
          </div>
        </div>
      </div>
    </nav>
  );
}
