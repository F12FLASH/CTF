import { AlertTriangle, ExternalLink } from "lucide-react";
import { useLanguage } from "./language-context";

export function ChallengeFooter() {
  const { t } = useLanguage();

  return (
    <footer className="border-t bg-muted/30 py-8">
      <div className="container mx-auto space-y-6 px-4">
        <div className="flex items-start gap-3 rounded-md border bg-card p-6">
          <AlertTriangle className="h-5 w-5 flex-shrink-0 text-primary" />
          <div className="space-y-2">
            <h3 className="font-heading font-semibold">{t("footerNote")}</h3>
            <p className="text-sm leading-relaxed text-muted-foreground">
              {t("footerText")}
            </p>
          </div>
        </div>

        <div className="space-y-4 text-center text-sm text-muted-foreground">
          <div>
            <p className="font-heading font-semibold">{t("credits")}</p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-4">
            <a
              href="https://github.com/bwall/HashPump"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 hover-elevate rounded-md px-2 py-1 transition-colors hover:text-primary"
              data-testid="link-hashpump"
            >
              {t("toolHashPump")}
              <ExternalLink className="h-3 w-3" />
            </a>
            <span className="text-border">•</span>
            <a
              href="https://hashcat.net/"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 hover-elevate rounded-md px-2 py-1 transition-colors hover:text-primary"
              data-testid="link-hashcat"
            >
              {t("toolHashcat")}
              <ExternalLink className="h-3 w-3" />
            </a>
            <span className="text-border">•</span>
            <a
              href="https://www.openwall.com/john/"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 hover-elevate rounded-md px-2 py-1 transition-colors hover:text-primary"
              data-testid="link-john"
            >
              {t("toolJohnTheRipper")}
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
