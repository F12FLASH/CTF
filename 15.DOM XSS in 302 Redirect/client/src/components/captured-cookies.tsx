import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Cookie, Copy, CheckCircle2, Trash2 } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import type { CapturedCookie } from "@shared/schema";

export function CapturedCookiesPanel() {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: cookies = [] } = useQuery<CapturedCookie[]>({
    queryKey: ["/api/cookies"],
    refetchInterval: 3000,
  });

  const clearCookiesMutation = useMutation({
    mutationFn: async () => {
      return await apiRequest("DELETE", "/api/cookies");
    },
    onSuccess: () => {
      toast({
        title: "Đã xóa cookies",
        description: "Tất cả cookies đã capture đã được xóa.",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/cookies"] });
    },
  });

  const handleCopy = async (cookie: string, id: string) => {
    await navigator.clipboard.writeText(cookie);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
    toast({
      title: "Đã sao chép cookie",
      description: "Giá trị cookie đã được sao chép vào clipboard.",
    });
  };

  return (
    <Card data-testid="card-captured-cookies">
      <CardHeader className="space-y-1">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="flex items-center justify-center w-8 h-8 rounded-md bg-primary/10">
              <Cookie className="w-4 h-4 text-primary" data-testid="icon-cookie" />
            </div>
            <CardTitle className="text-lg" data-testid="title-captured-cookies">Cookie Đã Capture</CardTitle>
          </div>
          {cookies.length > 0 && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => clearCookiesMutation.mutate()}
              disabled={clearCookiesMutation.isPending}
              data-testid="button-clear-cookies"
              className="gap-2 text-destructive hover:text-destructive"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Xóa Hết
            </Button>
          )}
        </div>
        <CardDescription data-testid="text-cookies-description">
          Cookie đã đánh cắp từ các cuộc tấn công XSS thành công
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-4">
        {cookies.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-center" data-testid="empty-state-cookies">
            <div className="flex items-center justify-center w-16 h-16 rounded-full bg-muted mb-4">
              <Cookie className="w-8 h-8 text-muted-foreground" />
            </div>
            <p className="text-sm font-medium mb-1">Chưa có cookie nào được capture</p>
            <p className="text-xs text-muted-foreground max-w-xs leading-relaxed">
              Khai thác thành công lỗ hổng để capture cookie admin tại đây
            </p>
          </div>
        ) : (
          <ScrollArea className="h-[280px]">
            <div className="space-y-3 pr-3">
              {cookies.map((cookie) => (
                <div
                  key={cookie.id}
                  className="p-4 rounded-md border bg-card space-y-3"
                  data-testid={`cookie-item-${cookie.id}`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2">
                        <Badge variant="secondary" className="text-xs">
                          Đã Capture
                        </Badge>
                        <span className="text-xs text-muted-foreground font-mono">
                          {new Date(cookie.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <code className="text-xs font-mono break-all text-foreground block p-2 rounded bg-muted/50">
                        {cookie.cookie}
                      </code>
                      {cookie.sourceUrl && (
                        <p className="text-xs text-muted-foreground mt-2 truncate">
                          Nguồn: {cookie.sourceUrl}
                        </p>
                      )}
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleCopy(cookie.cookie, cookie.id)}
                      data-testid={`button-copy-cookie-${cookie.id}`}
                      className="flex-shrink-0"
                    >
                      {copiedId === cookie.id ? (
                        <CheckCircle2 className="w-4 h-4 text-status-online" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        )}

        {cookies.length > 0 && (
          <div className="p-3 rounded-md bg-status-online/10 border border-status-online/20">
            <div className="flex items-start gap-2">
              <CheckCircle2 className="w-4 h-4 text-status-online mt-0.5 flex-shrink-0" />
              <p className="text-xs text-status-online leading-relaxed">
                Thành công! Bạn đã capture {cookies.length} cookie. 
                Kiểm tra xem có chứa flag không.
              </p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
