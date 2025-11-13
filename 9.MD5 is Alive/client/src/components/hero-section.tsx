import { Shield, Terminal, Code2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useLanguage } from "./language-context";

interface HeroSectionProps {
  onStartChallenge: () => void;
}

export function HeroSection({ onStartChallenge }: HeroSectionProps) {
  const { t } = useLanguage();

  return (
    <section className="relative min-h-[60vh] w-full overflow-hidden border-b bg-gradient-to-br from-background via-background to-accent/10">
      <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGRlZnM+PHBhdHRlcm4gaWQ9ImdyaWQiIHdpZHRoPSI2MCIgaGVpZ2h0PSI2MCIgcGF0dGVyblVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHBhdGggZD0iTSAxMCAwIEwgMCAwIDAgMTAiIGZpbGw9Im5vbmUiIHN0cm9rZT0iaHNsKHZhcigtLWJvcmRlcikpIiBzdHJva2Utd2lkdGg9IjEiLz48L3BhdHRlcm4+PC9kZWZzPjxyZWN0IHdpZHRoPSIxMDAlIiBoZWlnaHQ9IjEwMCUiIGZpbGw9InVybCgjZ3JpZCkiLz48L3N2Zz4=')] opacity-20" />
      
      <div className="container relative mx-auto px-4 py-16 md:py-24">
        <div className="mx-auto max-w-4xl text-center">
          <div className="mb-6 flex items-center justify-center gap-2">
            <Terminal className="h-8 w-8 text-primary md:h-10 md:w-10" />
          </div>

          <h1 className="font-heading mb-4 text-4xl font-bold tracking-tight md:text-5xl lg:text-6xl">
            {t("challengeTitle")}
          </h1>

          <p className="mb-8 text-base leading-relaxed text-muted-foreground md:text-lg">
            {t("challengeSubtitle")}
          </p>

          <div className="mb-8 flex flex-wrap items-center justify-center gap-3">
            <Badge variant="outline" className="gap-2 px-4 py-2 text-sm" data-testid="badge-category">
              <Code2 className="h-4 w-4" />
              {t("category")}
            </Badge>
            <Badge variant="destructive" className="gap-2 px-4 py-2 text-sm" data-testid="badge-difficulty">
              <Shield className="h-4 w-4" />
              {t("difficulty")}
            </Badge>
            <Badge variant="secondary" className="px-4 py-2 text-sm" data-testid="badge-technology">
              {t("technology")}
            </Badge>
          </div>

          <Button
            size="lg"
            onClick={onStartChallenge}
            className="gap-2"
            data-testid="button-start-challenge"
          >
            <Terminal className="h-5 w-5" />
            {t("startChallenge")}
          </Button>
        </div>
      </div>
    </section>
  );
}
