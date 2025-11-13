import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Header } from "@/components/Header";
import { HeroSection } from "@/components/HeroSection";
import { TechnicalSpecs } from "@/components/TechnicalSpecs";
import { CodeEditor } from "@/components/CodeEditor";
import { BinarySimulator } from "@/components/BinarySimulator";
import { FlagSubmission } from "@/components/FlagSubmission";
import { ExploitGuide } from "@/components/ExploitGuide";
import { Badge } from "@/components/ui/badge";
import { ChallengeData } from "@shared/schema";

export default function Challenge() {
  const [showChallenge, setShowChallenge] = useState(false);

  const { data: challenge, isLoading, error } = useQuery<Omit<ChallengeData, 'flag'>>({
    queryKey: ["/api/challenge/the-black-hole"],
  });

  const handleLaunchChallenge = () => {
    setShowChallenge(true);
    setTimeout(() => {
      document.getElementById("challenge-section")?.scrollIntoView({ behavior: "smooth" });
    }, 100);
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center" data-testid="loading-challenge">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading challenge...</p>
        </div>
      </div>
    );
  }

  if (error || !challenge) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center" data-testid="error-challenge">
          <p className="text-destructive mb-4">Failed to load challenge</p>
          <p className="text-sm text-muted-foreground">{error instanceof Error ? error.message : "Unknown error"}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      <Header />
      <main>
        <HeroSection challenge={challenge} onLaunchChallenge={handleLaunchChallenge} />
        
        <div id="challenge-section">
          <TechnicalSpecs challenge={challenge} />
          
          {showChallenge && (
            <>
              <CodeEditor />
              <BinarySimulator />
              <FlagSubmission />
              <ExploitGuide steps={challenge.exploitSteps} />
            </>
          )}
        </div>

        <footer className="border-t bg-card mt-16">
          <div className="container mx-auto px-4 py-8">
            <div className="flex flex-col md:flex-row items-center justify-between gap-4">
              <div className="text-center md:text-left">
                <p className="text-sm text-muted-foreground font-mono">
                  © 2025 Vietnamese CTF Platform. Built for security enthusiasts.
                </p>
              </div>
              <div className="flex items-center gap-4">
                <Badge variant="outline" className="font-mono text-xs">
                  Vietnam
                </Badge>
                <Badge variant="outline" className="font-mono text-xs">
                  Pwn
                </Badge>
                <Badge variant="outline" className="font-mono text-xs">
                  Binary Exploitation
                </Badge>
              </div>
            </div>
          </div>
        </footer>
      </main>
    </div>
  );
}
