import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Target, Play, CheckCircle2, Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { KeystreamRecovery } from "@shared/schema";

export function KnownPlaintextAttack() {
  const [knownPrefix, setKnownPrefix] = useState("VNFLAG{");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const attackMutation = useMutation({
    mutationFn: async (knownPrefix: string) => {
      return apiRequest<KeystreamRecovery>("POST", "/api/attack/known-plaintext", {
        knownPrefix,
      });
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/attack/keystream"] });
      toast({
        title: "Tấn Công Hoàn Tất",
        description: `Đã khôi phục keystream với độ tin cậy ${data.confidence.toFixed(1)}%.`,
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Tấn Công Thất Bại",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const runAttack = () => {
    if (!knownPrefix) return;
    attackMutation.mutate(knownPrefix);
  };

  const result = attackMutation.data;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Target className="h-5 w-5 text-primary" />
          Tấn Công Văn Bản Rõ Đã Biết
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label htmlFor="known-prefix" className="text-xs uppercase tracking-wider">
            Tiền Tố Văn Bản Rõ Đã Biết
          </Label>
          <Input
            id="known-prefix"
            type="text"
            value={knownPrefix}
            onChange={(e) => setKnownPrefix(e.target.value)}
            placeholder="vd: VNFLAG{"
            className="font-mono"
            disabled={attackMutation.isPending}
            data-testid="input-known-prefix"
          />
          <p className="text-xs text-muted-foreground">
            Nhập phần đầu đã biết của văn bản rõ để khôi phục keystream
          </p>
        </div>

        <Button
          onClick={runAttack}
          disabled={!knownPrefix || attackMutation.isPending}
          className="w-full gap-2"
          data-testid="button-run-attack"
        >
          {attackMutation.isPending ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Đang Tấn Công...
            </>
          ) : (
            <>
              <Play className="h-4 w-4" />
              Thực Thi Tấn Công Văn Bản Rõ
            </>
          )}
        </Button>

        {result && (
          <div className="space-y-4 pt-4 border-t">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5 text-green-500" />
              <span className="font-medium">Khôi Phục Keystream Hoàn Tất</span>
            </div>

            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wider text-muted-foreground">
                Keystream Đã Khôi Phục (Hex)
              </Label>
              <div className="p-4 bg-muted rounded-md font-mono text-xs break-all">
                {result.recoveredKeystream}
              </div>
            </div>

            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wider text-muted-foreground">
                Mức Độ Tin Cậy
              </Label>
              <div className="flex items-center gap-3">
                <Progress value={result.confidence} className="flex-1 h-2" />
                <Badge variant="secondary" className="font-mono">
                  {result.confidence.toFixed(1)}%
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground">
                {result.matchedCiphertexts} bản mã khớp với keystream đồng thuận
              </p>
            </div>

            {result.recoveredPlaintext && (
              <div className="space-y-2">
                <Label className="text-xs uppercase tracking-wider text-muted-foreground">
                  Xem Trước Văn Bản Đã Khôi Phục
                </Label>
                <div className="p-4 bg-muted rounded-md font-mono text-sm">
                  {result.recoveredPlaintext}
                </div>
              </div>
            )}
          </div>
        )}

        {!result && !attackMutation.isPending && (
          <div className="p-4 bg-muted/50 rounded-md text-sm text-muted-foreground">
            Tấn công này sử dụng tiền tố văn bản rõ đã biết để XOR với các bản mã, 
            tiết lộ keystream được sử dụng để mã hóa.
          </div>
        )}
      </CardContent>
    </Card>
  );
}
