import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Send, Loader2 } from "lucide-react";
import { useState } from "react";

interface TokenSubmissionProps {
  onSubmit: (token: string) => void;
  isPending: boolean;
}

export function TokenSubmission({ onSubmit, isPending }: TokenSubmissionProps) {
  const [token, setToken] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (token.trim()) {
      onSubmit(token.trim());
    }
  };

  return (
    <Card className="border-primary/30 bg-card/50 backdrop-blur-sm" data-testid="card-token-submission">
      <CardHeader className="gap-1 space-y-0 pb-4">
        <CardTitle className="text-xl font-mono">Gửi Token Đã Khai Thác</CardTitle>
        <CardDescription className="font-mono text-xs">
          Dán token JWT đã được sửa đổi của bạn để xác thực và chiếm flag
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <Textarea
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            className="font-mono text-sm min-h-32 bg-secondary/50 border-border resize-none"
            disabled={isPending}
            data-testid="input-token"
          />
          <Button
            type="submit"
            size="lg"
            className="w-full font-mono uppercase tracking-wider"
            disabled={!token.trim() || isPending}
            data-testid="button-submit-token"
          >
            {isPending ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Đang Xác Thực...
              </>
            ) : (
              <>
                <Send className="h-4 w-4 mr-2" />
                Gửi Token
              </>
            )}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
