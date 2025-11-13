import { useState, useEffect } from "react";
import { Send, Loader2, CheckCircle2, XCircle, AlertCircle, Lightbulb } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import type { FetchRequest, FetchResponse } from "@shared/schema";

interface URLFetcherProps {
  onResponse: (response: FetchResponse) => void;
  initialUrl?: string;
}

export function URLFetcher({ onResponse, initialUrl }: URLFetcherProps) {
  const [url, setUrl] = useState(initialUrl || "");

  useEffect(() => {
    if (initialUrl) {
      setUrl(initialUrl);
    }
  }, [initialUrl]);

  const fetchMutation = useMutation<FetchResponse, Error, FetchRequest>({
    mutationFn: async (data: FetchRequest) => {
      const response = await apiRequest("POST", "/api/fetch", data);
      return await response.json() as FetchResponse;
    },
    onSuccess: (data) => {
      onResponse(data);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) {
      fetchMutation.mutate({ url: url.trim() });
    }
  };

  // Real-time URL validation
  const getUrlValidation = () => {
    if (!url) return null;
    
    const lower = url.toLowerCase();
    if (lower.includes('localhost')) {
      return { type: 'error' as const, message: 'Phát hiện từ khóa "localhost"' };
    }
    if (lower.includes('127.0.0.1')) {
      return { type: 'error' as const, message: '127.0.0.1 bị chặn' };
    }
    if (lower.includes('.local')) {
      return { type: 'error' as const, message: 'Tên miền .local bị chặn' };
    }
    
    try {
      new URL(url);
      return { type: 'success' as const, message: 'Định dạng URL hợp lệ' };
    } catch {
      return { type: 'warning' as const, message: 'Định dạng URL không hợp lệ' };
    }
  };

  const validation = getUrlValidation();

  const getStatusIcon = () => {
    if (fetchMutation.isPending) {
      return <Loader2 className="w-5 h-5 text-primary animate-spin" />;
    }
    if (fetchMutation.data) {
      switch (fetchMutation.data.status) {
        case 'success':
          return <CheckCircle2 className="w-5 h-5 text-terminal-green" />;
        case 'blocked':
          return <XCircle className="w-5 h-5 text-terminal-red" />;
        case 'error':
          return <AlertCircle className="w-5 h-5 text-terminal-yellow" />;
        default:
          return null;
      }
    }
    return null;
  };

  return (
    <div className="bg-card border border-card-border rounded-md overflow-hidden shadow-glow-orange">
      {/* Terminal header */}
      <div className="bg-muted border-b border-border px-4 py-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-destructive" />
            <div className="w-3 h-3 rounded-full bg-terminal-yellow" />
            <div className="w-3 h-3 rounded-full bg-terminal-green" />
          </div>
          <span className="text-sm font-mono text-muted-foreground ml-2">Trình Fetch URL</span>
        </div>
        <div className="text-xs font-mono text-muted-foreground">
          {fetchMutation.data?.timing && `${fetchMutation.data.timing}ms`}
        </div>
      </div>

      {/* Input area */}
      <div className="p-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex flex-col gap-2">
            <label htmlFor="url-input" className="text-sm font-mono text-muted-foreground">
              URL Mục tiêu
            </label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Input
                  id="url-input"
                  data-testid="input-url"
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="http://example.com"
                  className="font-mono pr-10"
                  disabled={fetchMutation.isPending}
                />
                {!fetchMutation.isPending && getStatusIcon() && (
                  <div className="absolute right-3 top-1/2 -translate-y-1/2" data-testid="icon-status">
                    {getStatusIcon()}
                  </div>
                )}
                {fetchMutation.isPending && (
                  <div className="absolute right-3 top-1/2 -translate-y-1/2">
                    <div className="w-5 h-5 relative">
                      <div className="absolute inset-0 border-2 border-primary/30 rounded-full" />
                      <div className="absolute inset-0 border-2 border-primary border-t-transparent rounded-full animate-spin" data-testid="loader-mars-orbit" />
                    </div>
                  </div>
                )}
              </div>
              <Button
                data-testid="button-fetch-url"
                type="submit"
                disabled={fetchMutation.isPending || !url.trim()}
                className="gap-2"
              >
                {fetchMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Send className="w-4 h-4" />
                )}
                FETCH
              </Button>
            </div>
            
            {/* Real-time validation feedback */}
            {validation && (
              <div className={`text-xs font-mono flex items-center gap-2 ${
                validation.type === 'error' ? 'text-terminal-red' :
                validation.type === 'success' ? 'text-terminal-green' :
                'text-terminal-yellow'
              }`} data-testid={`validation-${validation.type}`}>
                <span>●</span>
                <span>{validation.message}</span>
              </div>
            )}
          </div>

          {/* Blocked patterns info */}
          <div className="bg-muted/50 rounded-md p-4 border border-border">
            <p className="text-xs font-mono text-muted-foreground mb-2">CÁC MẪU BỊ CHẶN</p>
            <div className="flex flex-wrap gap-2">
              {['127.0.0.1', 'localhost', '*.local', '0.0.0.0', '127.0.0.0/8'].map((pattern) => (
                <code
                  key={pattern}
                  className="px-2 py-0.5 bg-destructive/10 text-destructive rounded text-xs font-mono border border-destructive/20"
                >
                  {pattern}
                </code>
              ))}
            </div>
          </div>
        </form>

        {/* Quick help */}
        <div className="mt-4 text-xs text-muted-foreground font-mono flex items-start gap-2">
          <Lightbulb className="w-3 h-3 shrink-0 mt-0.5 text-primary" />
          <p>Mẹo: Thử các biểu diễn thay thế của localhost</p>
        </div>
      </div>
    </div>
  );
}
