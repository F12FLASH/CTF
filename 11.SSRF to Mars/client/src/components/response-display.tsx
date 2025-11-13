import { CheckCircle2, XCircle, AlertCircle, Copy, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import type { FetchResponse } from "@shared/schema";
import { useState } from "react";

interface ResponseDisplayProps {
  response: FetchResponse | null;
}

export function ResponseDisplay({ response }: ResponseDisplayProps) {
  const [copied, setCopied] = useState(false);

  // Safe JSON syntax highlighting with preserved indentation
  // React automatically escapes all text content, ensuring XSS safety
  const highlightJSON = (text: string): JSX.Element => {
    try {
      const parsed = JSON.parse(text);
      const formatted = JSON.stringify(parsed, null, 2);
      
      // Split into lines and apply syntax coloring while preserving indentation
      const lines = formatted.split('\n').map((line, lineIndex) => {
        // Extract leading whitespace and preserve it using non-breaking spaces
        const leadingSpaces = line.match(/^(\s*)/)?.[1] || '';
        const preservedSpaces = leadingSpaces.replace(/ /g, '\u00a0'); // Convert to non-breaking spaces
        const trimmed = line.trim();
        
        // Keys (lines with quotes and colons)
        if (trimmed.match(/^"[^"]+"\s*:/)) {
          const colonIndex = trimmed.indexOf(':');
          const key = trimmed.substring(0, colonIndex + 1);
          const value = trimmed.substring(colonIndex + 1);
          
          return (
            <div key={lineIndex}>
              {preservedSpaces}
              <span className="text-primary font-semibold">{key}</span>
              {value && <span className="text-terminal-green">{value}</span>}
            </div>
          );
        }
        
        // Number values
        if (trimmed.match(/^\d+,?$/)) {
          return (
            <div key={lineIndex}>
              {preservedSpaces}
              <span className="text-terminal-orange">{trimmed}</span>
            </div>
          );
        }
        
        // Boolean values
        if (trimmed.match(/^(true|false),?$/)) {
          return (
            <div key={lineIndex}>
              {preservedSpaces}
              <span className="text-terminal-yellow">{trimmed}</span>
            </div>
          );
        }
        
        // Null values
        if (trimmed.match(/^null,?$/)) {
          return (
            <div key={lineIndex}>
              {preservedSpaces}
              <span className="text-muted-foreground">{trimmed}</span>
            </div>
          );
        }
        
        // Default: render line as-is with preserved indentation
        const preservedLine = line.replace(/^ +/, match => match.replace(/ /g, '\u00a0'));
        return <div key={lineIndex}>{preservedLine}</div>;
      });
      
      return <>{lines}</>;
    } catch {
      // If JSON parsing fails, return plain text (React escapes automatically)
      return <>{text}</>;
    }
  };

  if (!response) {
    return (
      <div className="bg-card border border-card-border rounded-md overflow-hidden" data-testid="response-empty">
        <div className="bg-muted border-b border-border px-4 py-2">
          <span className="text-sm font-mono text-muted-foreground">Response</span>
        </div>
        <div className="p-12 text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-muted mb-4">
            <AlertCircle className="w-8 h-8 text-muted-foreground" data-testid="icon-no-response" />
          </div>
          <p className="text-muted-foreground font-mono text-sm" data-testid="text-no-response">
            Chưa có yêu cầu nào. Thử fetch một URL ở trên.
          </p>
        </div>
      </div>
    );
  }

  const getStatusColor = () => {
    switch (response.status) {
      case 'success':
        return 'text-terminal-green';
      case 'blocked':
        return 'text-terminal-red';
      case 'error':
        return 'text-terminal-yellow';
      default:
        return 'text-muted-foreground';
    }
  };

  const getStatusIcon = () => {
    switch (response.status) {
      case 'success':
        return <CheckCircle2 className="w-5 h-5 text-terminal-green" />;
      case 'blocked':
        return <XCircle className="w-5 h-5 text-terminal-red" />;
      case 'error':
        return <AlertCircle className="w-5 h-5 text-terminal-yellow" />;
      default:
        return null;
    }
  };

  const handleCopy = () => {
    if (response.response) {
      navigator.clipboard.writeText(response.response);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const isJSON = response.response && response.response.trim().startsWith('{');

  return (
    <div className="bg-card border border-card-border rounded-md overflow-hidden" data-testid="response-display">
      {/* Terminal header */}
      <div className="bg-muted border-b border-border px-4 py-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          {getStatusIcon()}
          <span className="text-sm font-mono text-muted-foreground" data-testid="text-response-header">Phản hồi</span>
        </div>
        {response.response && (
          <Button
            data-testid="button-copy-response"
            size="sm"
            variant="ghost"
            onClick={handleCopy}
            className="gap-2 h-7"
          >
            {copied ? (
              <>
                <Check className="w-3 h-3" />
                <span className="text-xs">Đã sao</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span className="text-xs">Sao chép</span>
              </>
            )}
          </Button>
        )}
      </div>

      {/* Status info */}
      <div className="p-4 border-b border-border bg-muted/30">
        <div className="flex flex-wrap gap-4 text-sm font-mono mb-3">
          <div>
            <span className="text-muted-foreground">Trạng thái: </span>
            <Badge 
              variant={response.status === 'success' ? 'default' : response.status === 'blocked' ? 'destructive' : 'secondary'}
              className="font-mono text-xs"
              data-testid={`badge-status-${response.status}`}
            >
              {response.status.toUpperCase()}
            </Badge>
          </div>
          {response.statusCode && (
            <div>
              <span className="text-muted-foreground">Mã: </span>
              <span className="text-foreground" data-testid="text-status-code">{response.statusCode}</span>
            </div>
          )}
          {response.timing && (
            <div>
              <span className="text-muted-foreground">Thời gian: </span>
              <span className="text-foreground" data-testid="text-timing">{response.timing}ms</span>
            </div>
          )}
        </div>
        
        {response.blockedReason && (
          <div className="mb-2 text-sm">
            <span className="text-muted-foreground font-mono">Lý do: </span>
            <span className="text-terminal-red font-mono" data-testid="text-blocked-reason">{response.blockedReason}</span>
          </div>
        )}

        {response.headers && Object.keys(response.headers).length > 0 && (
          <div className="mt-3 pt-3 border-t border-border">
            <p className="text-xs font-mono text-muted-foreground mb-2">TIÊU ĐỀ</p>
            <div className="space-y-1">
              {Object.entries(response.headers).slice(0, 5).map(([key, value]) => (
                <div key={key} className="text-xs font-mono">
                  <span className="text-primary">{key}:</span>{" "}
                  <span className="text-muted-foreground">{value}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Response body */}
      <ScrollArea className="h-[300px]">
        <div className="p-4">
          {response.message && (
            <div className="mb-3">
              <p className={`text-sm font-mono ${getStatusColor()}`} data-testid="text-response-message">
                {response.message}
              </p>
            </div>
          )}
          
          {response.response ? (
            <div className="relative">
              {isJSON && (
                <div className="absolute top-2 right-2 z-10">
                  <Badge variant="outline" className="text-xs font-mono" data-testid="badge-json">
                    JSON
                  </Badge>
                </div>
              )}
              <pre className="text-sm font-mono text-foreground whitespace-pre-wrap break-all bg-background/50 p-3 rounded border border-border" data-testid="pre-response-body">
                {isJSON ? highlightJSON(response.response) : <>{response.response}</>}
              </pre>
            </div>
          ) : (
            <p className="text-sm font-mono text-muted-foreground italic" data-testid="text-no-body">
              Không có nội dung phản hồi
            </p>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
