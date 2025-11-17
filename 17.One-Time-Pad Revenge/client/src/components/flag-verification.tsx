import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Flag, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import type { FlagVerificationResponse } from "@shared/schema";

export function FlagVerification() {
  const [flag, setFlag] = useState("");

  const verifyMutation = useMutation({
    mutationFn: async (flag: string) => {
      return apiRequest<FlagVerificationResponse>("POST", "/api/flag/verify", { flag });
    },
  });

  const verifyFlag = () => {
    if (!flag) return;
    verifyMutation.mutate(flag);
  };

  const result = verifyMutation.data;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Flag className="h-5 w-5 text-primary" />
          Xác Minh Flag
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label htmlFor="flag-input" className="text-xs uppercase tracking-wider">
            Nộp Flag
          </Label>
          <Input
            id="flag-input"
            type="text"
            value={flag}
            onChange={(e) => setFlag(e.target.value)}
            placeholder="VNFLAG{...}"
            className="font-mono"
            disabled={verifyMutation.isPending}
            data-testid="input-flag"
          />
          <p className="text-xs text-muted-foreground">
            Nhập flag đã khôi phục để xác minh
          </p>
        </div>

        <Button
          onClick={verifyFlag}
          disabled={!flag || verifyMutation.isPending}
          className="w-full"
          size="lg"
          data-testid="button-verify-flag"
        >
          {verifyMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          {verifyMutation.isPending ? "Đang Xác Minh..." : "Xác Minh Flag"}
        </Button>

        {result && (
          <div
            className={`
              p-6 rounded-md border-2 space-y-4
              ${result.valid 
                ? "bg-green-500/10 border-green-500/50" 
                : "bg-destructive/10 border-destructive/50"
              }
            `}
          >
            <div className="flex items-center gap-3">
              {result.valid ? (
                <>
                  <CheckCircle2 className="h-6 w-6 text-green-500" />
                  <div>
                    <p className="font-semibold text-lg">Flag Hợp Lệ!</p>
                    <p className="text-sm text-muted-foreground">{result.message}</p>
                  </div>
                </>
              ) : (
                <>
                  <XCircle className="h-6 w-6 text-destructive" />
                  <div>
                    <p className="font-semibold text-lg">Flag Không Hợp Lệ</p>
                    <p className="text-sm text-muted-foreground">{result.message}</p>
                  </div>
                </>
              )}
            </div>

            <div className="space-y-3 pt-4 border-t">
              <div className="space-y-1">
                <Label className="text-xs uppercase tracking-wider text-muted-foreground">
                  SHA256 Flag Đã Nhập
                </Label>
                <div className="p-3 bg-card rounded-md font-mono text-xs break-all">
                  {result.providedHash}
                </div>
              </div>

              {result.expectedHash && (
                <div className="space-y-1">
                  <Label className="text-xs uppercase tracking-wider text-muted-foreground">
                    Hash Mong Đợi
                  </Label>
                  <div className="p-3 bg-card rounded-md font-mono text-xs break-all">
                    {result.expectedHash}
                  </div>
                </div>
              )}
            </div>

            {result.valid && (
              <div className="flex items-center justify-center gap-2 pt-4">
                <Badge variant="secondary" className="text-sm">
                  Hoàn Thành Thử Thách
                </Badge>
              </div>
            )}
          </div>
        )}

        {!result && (
          <div className="p-4 bg-muted/50 rounded-md space-y-3">
            <p className="text-sm text-muted-foreground">
              Định dạng flag: <span className="font-mono text-foreground">VNFLAG{'{...}'}</span>
            </p>
            <p className="text-xs text-muted-foreground">
              Xác minh sử dụng so sánh hash SHA256. Hệ thống kiểm tra rằng 
              SHA256(flag) khớp với hash keystream mong đợi.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
