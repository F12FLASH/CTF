import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, XCircle, Clock, AlertCircle } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import type { ExploitAttempt } from "@shared/schema";
import { Skeleton } from "@/components/ui/skeleton";
import { useLanguage } from "@/components/app-sidebar";
import { Alert, AlertDescription } from "@/components/ui/alert";

export default function History() {
  const { lang } = useLanguage();
  const { data: attempts = [], isLoading, error } = useQuery<ExploitAttempt[]>({
    queryKey: ["/api/attempts"],
  });

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "success":
        return <CheckCircle2 className="h-4 w-4" />;
      case "crash":
        return <XCircle className="h-4 w-4" />;
      default:
        return <Clock className="h-4 w-4" />;
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

  const getResultLabel = (result: string) => {
    if (lang === "vi") {
      switch (result) {
        case "shell": return "Shell";
        case "crash": return "Lỗi";
        case "timeout": return "Hết Giờ";
        default: return result;
      }
    }
    return result;
  };

  return (
    <div className="p-4 lg:p-6 space-y-4 lg:space-y-6 h-full overflow-y-auto">
      <div className="space-y-2">
        <h1 className="text-2xl font-bold">
          {lang === "vi" ? "Lịch Sử Thử Nghiệm" : "Attempt History"}
        </h1>
        <p className="text-sm text-muted-foreground">
          {lang === "vi"
            ? "Xem lại các lần thử khai thác và kết quả trong quá khứ"
            : "Review past exploitation attempts and results"}
        </p>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>
            {lang === "vi" 
              ? "Không thể tải lịch sử. Vui lòng thử lại."
              : "Failed to load history. Please try again."}
          </AlertDescription>
        </Alert>
      )}

      {isLoading ? (
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => (
            <Skeleton key={i} className="h-40" />
          ))}
        </div>
      ) : (
        <div className="space-y-3">
          {attempts.length === 0 ? (
            <Card className="p-12 text-center">
              <p className="text-sm text-muted-foreground">
                {lang === "vi"
                  ? "Chưa có lịch sử thử nghiệm"
                  : "No attempt history yet"}
              </p>
            </Card>
          ) : (
            attempts.map((attempt) => (
              <Card key={attempt.id} className="p-4 lg:p-6 space-y-4 hover-elevate">
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                  <Badge variant={getStatusVariant(attempt.status)} className="gap-1">
                    {getStatusIcon(attempt.status)}
                    <span className="text-xs uppercase">{getStatusLabel(attempt.status)}</span>
                  </Badge>
                  <span className="text-sm text-muted-foreground">
                    {new Date(attempt.timestamp).toLocaleString()}
                  </span>
                </div>

                <div className="space-y-2">
                  <div className="text-xs text-muted-foreground uppercase tracking-wide">
                    Payload
                  </div>
                  <div className="bg-muted p-3 rounded font-mono text-xs overflow-x-auto">
                    {attempt.payloadPreview}
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                  <div className="space-y-1">
                    <div className="text-xs text-muted-foreground uppercase tracking-wide">
                      {lang === "vi" ? "Kết Quả" : "Result"}
                    </div>
                    <div className="font-mono">{getResultLabel(attempt.result)}</div>
                  </div>
                  <div className="space-y-1">
                    <div className="text-xs text-muted-foreground uppercase tracking-wide">
                      {lang === "vi" ? "Thời Gian" : "Duration"}
                    </div>
                    <div className="font-mono">{attempt.duration}ms</div>
                  </div>
                </div>
              </Card>
            ))
          )}
        </div>
      )}
    </div>
  );
}
