import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, Circle, Trophy } from "lucide-react";
import { type Progress as ProgressType } from "@shared/schema";

const CHALLENGE_SECTIONS = [
  { id: "overview", title: "Tổng quan thử thách" },
  { id: "static-analysis", title: "Phân tích tĩnh" },
  { id: "gdb-scripting", title: "GDB Scripting" },
  { id: "memory-tracing", title: "Memory Tracing" },
  { id: "ld-preload", title: "LD_PRELOAD Hook" },
  { id: "binary-patching", title: "Binary Patching" },
];

export function ProgressTracker() {
  const { data: progressData = [] } = useQuery<ProgressType[]>({
    queryKey: ["/api/progress"],
  });

  const completedCount = progressData.filter(p => p.completed).length;
  const totalSections = CHALLENGE_SECTIONS.length;
  const progressPercentage = totalSections > 0 ? (completedCount / totalSections) * 100 : 0;

  const isSectionCompleted = (sectionId: string) => {
    return progressData.some(p => p.sectionId === sectionId && p.completed);
  };

  return (
    <Card className="border-primary/20" data-testid="card-progress">
      <CardHeader>
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10 border border-primary/20">
            <Trophy className="h-5 w-5 text-primary" />
          </div>
          <div className="flex-1">
            <CardTitle className="text-xl">Tiến độ</CardTitle>
            <CardDescription>{completedCount} / {totalSections} phần đã hoàn thành</CardDescription>
          </div>
          <Badge variant="secondary" className="font-mono">
            {Math.round(progressPercentage)}%
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <Progress value={progressPercentage} className="h-2" data-testid="progress-bar" />
        <div className="space-y-2">
          {CHALLENGE_SECTIONS.map((section) => {
            const completed = isSectionCompleted(section.id);
            return (
              <div
                key={section.id}
                className="flex items-center gap-3 p-2 rounded-md hover-elevate"
                data-testid={`section-${section.id}`}
              >
                {completed ? (
                  <CheckCircle2 className="h-4 w-4 text-primary flex-shrink-0" />
                ) : (
                  <Circle className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                )}
                <span className={`text-sm ${completed ? 'text-foreground' : 'text-muted-foreground'}`}>
                  {section.title}
                </span>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
