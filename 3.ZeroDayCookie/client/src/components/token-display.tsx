import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Copy, Check, Key, Lock } from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";

interface TokenDisplayProps {
  currentToken: string;
  publicKey?: string;
}

export function TokenDisplay({ currentToken, publicKey }: TokenDisplayProps) {
  const [copied, setCopied] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);
  const { toast } = useToast();

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(currentToken);
      setCopied(true);
      toast({
        description: "Đã sao chép token vào clipboard",
        duration: 2000,
      });
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      toast({
        description: "Không thể sao chép token",
        variant: "destructive",
        duration: 2000,
      });
    }
  };

  const copyKeyToClipboard = async () => {
    if (!publicKey) return;
    try {
      await navigator.clipboard.writeText(publicKey);
      setCopiedKey(true);
      toast({
        description: "Đã sao chép khóa công khai vào clipboard",
        duration: 2000,
      });
      setTimeout(() => setCopiedKey(false), 2000);
    } catch (error) {
      toast({
        description: "Không thể sao chép khóa",
        variant: "destructive",
        duration: 2000,
      });
    }
  };

  const parts = currentToken.split(".");
  
  const base64UrlToBase64 = (base64Url: string): string => {
    let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const padding = base64.length % 4;
    if (padding > 0) {
      base64 += '='.repeat(4 - padding);
    }
    return base64;
  };
  
  const decodeHeader = (headerSegment: string): any => {
    try {
      if (!headerSegment || headerSegment.length === 0) {
        return {};
      }
      const base64 = base64UrlToBase64(headerSegment);
      const decoded = atob(base64);
      return JSON.parse(decoded);
    } catch (error) {
      toast({
        title: "Cảnh báo",
        description: "Không thể giải mã header JWT. Token có thể bị lỗi định dạng.",
        variant: "destructive",
        duration: 3000,
      });
      return { alg: 'unknown', typ: 'JWT' };
    }
  };
  
  const decodedHeader = decodeHeader(parts[0] || '');

  return (
    <div className="space-y-4">
      <Card className="border-primary/30 bg-card/50 backdrop-blur-sm" data-testid="card-token-display">
        <CardHeader className="gap-1 space-y-0 pb-4">
          <div className="flex items-center justify-between">
            <CardTitle className="text-xl font-mono flex items-center gap-2">
              <Key className="h-5 w-5 text-primary" />
              Token Hiện Tại Của Bạn
            </CardTitle>
            <Button
              size="sm"
              variant="ghost"
              onClick={copyToClipboard}
              className="font-mono"
              data-testid="button-copy-token"
            >
              {copied ? (
                <>
                  <Check className="h-4 w-4 mr-2" />
                  Đã Sao
                </>
              ) : (
                <>
                  <Copy className="h-4 w-4 mr-2" />
                  Sao Chép
                </>
              )}
            </Button>
          </div>
          <CardDescription className="font-mono text-xs">
            Thuật toán: <span className="text-primary">{decodedHeader.alg || 'RS256'}</span> | Loại:{" "}
            <span className="text-chart-2">{decodedHeader.typ || 'JWT'}</span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="bg-secondary/50 border border-border rounded-md p-4 font-mono text-sm break-all space-y-2">
            <div className="flex items-start gap-2">
              <span className="text-chart-3 shrink-0">header:</span>
              <span className="text-foreground opacity-80" data-testid="text-jwt-header">
                {parts[0]}
              </span>
            </div>
            <div className="h-px bg-border" />
            <div className="flex items-start gap-2">
              <span className="text-chart-2 shrink-0">payload:</span>
              <span className="text-foreground opacity-80" data-testid="text-jwt-payload">
                {parts[1]}
              </span>
            </div>
            <div className="h-px bg-border" />
            <div className="flex items-start gap-2">
              <span className="text-chart-4 shrink-0">signature:</span>
              <span className="text-foreground opacity-80" data-testid="text-jwt-signature">
                {parts[2]}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>

      {publicKey && (
        <Card className="border-accent/30 bg-accent/20 backdrop-blur-sm" data-testid="card-public-key">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg font-mono flex items-center gap-2">
                <Lock className="h-5 w-5 text-accent-foreground" />
                Khóa Công Khai RS256 Của Máy Chủ
              </CardTitle>
              <Button
                size="sm"
                variant="ghost"
                onClick={copyKeyToClipboard}
                className="font-mono"
              >
                {copiedKey ? (
                  <>
                    <Check className="h-4 w-4 mr-2" />
                    Đã Sao
                  </>
                ) : (
                  <>
                    <Copy className="h-4 w-4 mr-2" />
                    Sao Chép
                  </>
                )}
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="bg-secondary/50 border border-border rounded-md p-3 font-mono text-xs break-all max-h-40 overflow-y-auto">
              {publicKey}
            </div>
            <p className="font-mono text-xs text-accent-foreground mt-3">
              Đây là khóa mà máy chủ sử dụng để xác minh token RS256. Bạn có thể sử dụng nó để khai thác lỗ hổng!
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
