import { MatrixBackground } from "@/components/matrix-background";
import { Navigation } from "@/components/navigation";
import { TerminalHero } from "@/components/terminal-hero";
import { StatsBar } from "@/components/stats-bar";
import { OverviewCards } from "@/components/overview-cards";
import { TechnicalSpecs } from "@/components/technical-specs";
import { SolutionMethods } from "@/components/solution-methods";
import { ToolsGrid } from "@/components/tools-grid";
import { FlagSubmission } from "@/components/flag-submission";
import { SubmissionHistory } from "@/components/submission-history";

export default function Home() {
  return (
    <div className="relative min-h-screen">
      <MatrixBackground />
      <Navigation />
      
      <main className="relative z-10">
        <TerminalHero />
        <StatsBar />
        <OverviewCards />
        <TechnicalSpecs />
        <div id="solution-methods">
          <SolutionMethods />
        </div>
        <ToolsGrid />
        <FlagSubmission />
        <SubmissionHistory />
      </main>

      <footer className="relative z-10 border-t border-border bg-card/50 backdrop-blur-sm py-8 mt-16">
        <div className="max-w-7xl mx-auto px-6 text-center">
          <p className="text-sm text-muted-foreground font-mono">
            Quantum Crackme CTF © 2025 | Master-Level Reverse Engineering Challenge
          </p>
          <p className="text-xs text-muted-foreground mt-2">
            Built with <span className="text-primary">♥</span> for security researchers
          </p>
        </div>
      </footer>
    </div>
  );
}
