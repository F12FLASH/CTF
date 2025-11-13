import { Download, Target, Trophy } from "lucide-react";

export function StatsBar() {
  return (
    <section className="border-y border-border bg-card/50 backdrop-blur-sm sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-6 py-4">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 sm:gap-4">
          <div className="flex items-center gap-3" data-testid="stat-downloads">
            <div className="p-2 rounded-md bg-primary/10 text-primary">
              <Download className="w-5 h-5" />
            </div>
            <div>
              <div className="text-2xl font-bold font-mono" data-testid="text-download-count">1,247</div>
              <div className="text-xs text-muted-foreground uppercase tracking-wider">Downloads</div>
            </div>
          </div>

          <div className="flex items-center gap-3" data-testid="stat-attempts">
            <div className="p-2 rounded-md bg-chart-4/10 text-chart-4">
              <Target className="w-5 h-5" />
            </div>
            <div>
              <div className="text-2xl font-bold font-mono" data-testid="text-attempt-count">3,891</div>
              <div className="text-xs text-muted-foreground uppercase tracking-wider">Attempts</div>
            </div>
          </div>

          <div className="flex items-center gap-3" data-testid="stat-solves">
            <div className="p-2 rounded-md bg-primary/10 text-primary">
              <Trophy className="w-5 h-5" />
            </div>
            <div>
              <div className="text-2xl font-bold font-mono" data-testid="text-solve-count">42</div>
              <div className="text-xs text-muted-foreground uppercase tracking-wider">Solves</div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
