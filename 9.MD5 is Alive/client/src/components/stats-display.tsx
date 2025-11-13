import { Activity } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useLanguage } from "./language-context";

interface StatsDisplayProps {
  queryCount: number;
  attemptCount: number;
}

export function StatsDisplay({ queryCount, attemptCount }: StatsDisplayProps) {
  const { t } = useLanguage();

  return (
    <div className="flex flex-wrap items-center gap-3" data-testid="stats-display">
      <div className="flex items-center gap-2">
        <Activity className="h-4 w-4 text-muted-foreground" />
        <span className="text-sm font-medium text-muted-foreground">
          {t("totalQueries")}:
        </span>
      </div>
      <Badge variant="secondary" data-testid="badge-query-count">
        {queryCount} {t("queryCount")}
      </Badge>
      <Badge variant="secondary" data-testid="badge-attempt-count">
        {attemptCount} {t("attemptCount")}
      </Badge>
    </div>
  );
}
