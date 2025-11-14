import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Bot, Activity, Circle } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

interface BotStatus {
  status: "idle" | "visiting" | "completed";
  lastVisit?: string;
  visitCount: number;
}

export function BotStatusPanel() {
  const { data: botStatus } = useQuery<BotStatus>({
    queryKey: ["/api/bot/status"],
    refetchInterval: 2000,
  });

  const status = botStatus?.status || "idle";
  const statusConfig = {
    idle: { color: "text-muted-foreground", bg: "bg-muted", label: "Nghỉ", icon: Circle },
    visiting: { color: "text-status-away", bg: "bg-status-away/10", label: "Đang truy cập", icon: Activity },
    completed: { color: "text-status-online", bg: "bg-status-online/10", label: "Hoàn tất", icon: Circle },
  };

  const config = statusConfig[status];
  const StatusIcon = config.icon;

  return (
    <Card data-testid="card-bot-status">
      <CardHeader className="space-y-1">
        <div className="flex items-center gap-2">
          <div className="flex items-center justify-center w-8 h-8 rounded-md bg-primary/10">
            <Bot className="w-4 h-4 text-primary" data-testid="icon-bot" />
          </div>
          <CardTitle className="text-lg" data-testid="title-bot-status">Trạng Thái Bot Admin</CardTitle>
        </div>
        <CardDescription data-testid="text-bot-description">
          Giám sát hoạt động bot theo thời gian thực
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-4">
        <div className="flex items-center gap-3 p-4 rounded-md border bg-card" data-testid="status-display">
          <div className={`flex items-center justify-center w-10 h-10 rounded-full ${config.bg}`}>
            <StatusIcon className={`w-5 h-5 ${config.color}`} />
          </div>
          <div className="flex-1">
            <p className="text-sm font-medium" data-testid="text-status-label">Trạng Thái Hiện Tại</p>
            <p className="text-xs text-muted-foreground" data-testid="text-status-message">
              Bot hiện đang {status === "visiting" ? "truy cập một URL" : status === "idle" ? "nghỉ" : "hoàn tất"}
            </p>
          </div>
          <Badge variant={status === "idle" ? "outline" : "default"} data-testid="badge-bot-status">
            {config.label}
          </Badge>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Tổng Lượt Truy Cập</span>
            <span className="font-mono font-medium" data-testid="text-visit-count">
              {botStatus?.visitCount || 0}
            </span>
          </div>
          {botStatus?.lastVisit && (
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Lần Cuối</span>
              <span className="font-mono text-xs">
                {new Date(botStatus.lastVisit).toLocaleTimeString()}
              </span>
            </div>
          )}
        </div>

        <div className="p-3 rounded-md bg-muted/50 border">
          <p className="text-xs text-muted-foreground leading-relaxed">
            Bot mô phỏng một người dùng admin đã xác thực. Khi được kích hoạt, nó sẽ truy cập
            URL của bạn với cookie admin chứa flag.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
