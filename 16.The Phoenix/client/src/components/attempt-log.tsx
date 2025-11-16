import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { ExploitAttempt } from "@shared/schema";
import { CheckCircle2, XCircle, Clock } from "lucide-react";
import { useLanguage } from "./app-sidebar";

interface AttemptLogProps {
  attempts: ExploitAttempt[];
}

export function AttemptLog({ attempts }: AttemptLogProps) {
  const { lang } = useLanguage();
  
  const getStatusIcon = (status: string) => {
    switch (status) {
      case "success":
        return <CheckCircle2 className="h-3 w-3" />;
      case "crash":
        return <XCircle className="h-3 w-3" />;
      default:
        return <Clock className="h-3 w-3" />;
    }
  };

  const getStatusVariant = (status: string): "default" | "destructive" | "secondary" => {
    switch (status) {
      case "success":
        return "default";
      case "crash":
        return "destructive";
      default:
        return "secondary";
    }
  };

  const getStatusLabel = (status: string) => {
    if (lang === "vi") {
      switch (status) {
        case "success": return "Thành Công";
        case "crash": return "Lỗi";
        case "timeout": return "Hết Giờ";
        default: return status;
      }
    }
    return status;
  };

  return (
    <div className="space-y-4" data-testid="attempt-log">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">
          {lang === "vi" ? "Thử Nghiệm Gần Đây" : "Recent Attempts"}
        </h3>
        <Badge variant="secondary" className="text-xs">
          {attempts.length}
        </Badge>
      </div>
      <ScrollArea className="h-[500px]">
        <div className="space-y-2">
          {attempts.length === 0 ? (
            <div className="text-center py-12 text-sm text-muted-foreground">
              {lang === "vi" 
                ? "Chưa có thử nghiệm nào. Bắt đầu xây dựng exploit của bạn!"
                : "No attempts yet. Start building your exploit!"}
            </div>
          ) : (
            attempts.map((attempt) => (
              <div
                key={attempt.id}
                className="border rounded-md p-3 space-y-2 hover-elevate"
                data-testid={`attempt-${attempt.id}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <Badge variant={getStatusVariant(attempt.status)} className="gap-1">
                    {getStatusIcon(attempt.status)}
                    <span className="text-xs uppercase">{getStatusLabel(attempt.status)}</span>
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    {new Date(attempt.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <div className="font-mono text-xs bg-muted p-2 rounded overflow-x-auto">
                  {attempt.payloadPreview}
                </div>
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                  <span>
                    {lang === "vi" ? "Kết Quả" : "Result"}: {attempt.result}
                  </span>
                  <span>
                    {lang === "vi" ? "Thời Gian" : "Duration"}: {attempt.duration}ms
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
