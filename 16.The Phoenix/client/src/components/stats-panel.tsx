import { Card } from "@/components/ui/card";
import { Activity, Target, Clock, Zap } from "lucide-react";
import { useLanguage } from "./app-sidebar";

interface StatsPanelProps {
  totalAttempts: number;
  successRate: number;
  avgTime: number;
  currentStreak: number;
}

export function StatsPanel({
  totalAttempts,
  successRate,
  avgTime,
  currentStreak,
}: StatsPanelProps) {
  const { lang } = useLanguage();
  
  const stats = [
    {
      label: "Total Attempts",
      labelVi: "Tổng Thử Nghiệm",
      value: totalAttempts,
      icon: Activity,
    },
    {
      label: "Success Rate",
      labelVi: "Tỷ Lệ Thành Công",
      value: `${successRate}%`,
      icon: Target,
    },
    {
      label: "Avg Time",
      labelVi: "Thời Gian TB",
      value: `${avgTime}ms`,
      icon: Clock,
    },
    {
      label: "Streak",
      labelVi: "Chuỗi Liên Tiếp",
      value: currentStreak,
      icon: Zap,
    },
  ];

  return (
    <div className="space-y-4" data-testid="stats-panel">
      <h3 className="text-sm font-semibold">
        {lang === "vi" ? "Thống Kê" : "Statistics"}
      </h3>
      <div className="grid grid-cols-2 gap-3">
        {stats.map((stat, index) => (
          <Card key={index} className="p-3 space-y-1">
            <div className="flex items-center gap-2">
              <stat.icon className="h-3 w-3 text-muted-foreground" />
              <span className="text-xs text-muted-foreground uppercase tracking-wide">
                {lang === "vi" ? stat.labelVi : stat.label}
              </span>
            </div>
            <div className="text-2xl font-bold" data-testid={`stat-${stat.label.toLowerCase().replace(' ', '-')}`}>
              {stat.value}
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
