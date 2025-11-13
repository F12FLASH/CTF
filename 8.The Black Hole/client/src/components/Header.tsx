import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Terminal, Globe } from "lucide-react";
import { useLanguage } from "@/contexts/LanguageContext";

export function Header() {
  const { language, setLanguage, t } = useLanguage();

  return (
    <header className="sticky top-0 z-50 w-full border-b bg-card/95 backdrop-blur supports-[backdrop-filter]:bg-card/80">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary" data-testid="logo-icon">
              <Terminal className="h-5 w-5 text-primary-foreground" />
            </div>
            <div>
              <h1 className="font-heading text-lg font-semibold tracking-tight" data-testid="text-site-title">
                {t("CTF Platform", "Nền tảng CTF")}
              </h1>
              <p className="text-xs text-muted-foreground" data-testid="text-site-subtitle">
                {t("Vietnamese Security Challenges", "Thử thách bảo mật Việt Nam")}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Badge variant="outline" className="font-mono text-xs" data-testid="badge-status-live">
              <span className="mr-1.5 inline-block h-2 w-2 rounded-full bg-primary animate-pulse" />
              {t("Live", "Trực tuyến")}
            </Badge>
            
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setLanguage(language === "en" ? "vi" : "en")}
              className="gap-2"
              data-testid="button-language-toggle"
            >
              <Globe className="h-4 w-4" />
              <span className="text-sm font-medium">{language === "en" ? "VI" : "EN"}</span>
            </Button>
          </div>
        </div>
      </div>
    </header>
  );
}
