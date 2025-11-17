import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Lock, Loader2 } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { EncryptResponse } from "@shared/schema";

export function EncryptionSimulator() {
  const [plaintext, setPlaintext] = useState("");
  const { toast } = useToast();

  const encryptMutation = useMutation({
    mutationFn: async (data: { plaintext: string }) => {
      return apiRequest<EncryptResponse>("POST", "/api/encrypt", data);
    },
    onSuccess: () => {
      toast({
        title: "Mã Hóa Thành Công",
        description: "Văn bản đã được mã hóa bằng OTP với key ngẫu nhiên.",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Mã Hóa Thất Bại",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleEncrypt = () => {
    if (!plaintext) return;
    
    encryptMutation.mutate({
      plaintext,
    });
  };

  const result = encryptMutation.data;

  const xorVisualization = (text: string, key: string) => {
    if (!text || !key) return "";
    const minLength = Math.min(text.length, key.length / 2, 32);
    const keyBytes = key.match(/.{2}/g) || [];
    return Array.from({ length: minLength }, (_, i) => {
      const charCode = text.charCodeAt(i) ^ parseInt(keyBytes[i], 16);
      return charCode.toString(16).padStart(2, "0");
    }).join(" ");
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Lock className="h-5 w-5 text-primary" />
          <span>Mô Phỏng Mã Hóa OTP</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label htmlFor="plaintext" className="text-xs uppercase tracking-wider">
            Văn Bản Gốc
          </Label>
          <Textarea
            id="plaintext"
            placeholder="Nhập văn bản để mã hóa..."
            value={plaintext}
            onChange={(e) => setPlaintext(e.target.value)}
            className="h-32 font-mono text-sm resize-none"
            data-testid="input-plaintext"
            disabled={encryptMutation.isPending}
          />
        </div>

        <div className="p-3 bg-muted/50 rounded-md text-sm text-muted-foreground">
          <p className="flex items-center gap-2">
            <span className="text-primary">ℹ️</span>
            Key ngẫu nhiên sẽ được tự động tạo cho mỗi lần mã hóa
          </p>
        </div>

        <Button 
          onClick={handleEncrypt}
          className="w-full"
          disabled={!plaintext || encryptMutation.isPending}
          data-testid="button-encrypt"
        >
          {encryptMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          {encryptMutation.isPending ? "Đang Mã Hóa..." : "Mã Hóa với OTP"}
        </Button>

        {result && (
          <div className="space-y-4 pt-4 border-t">
            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wider text-muted-foreground">
                Bản Mã (Hex)
              </Label>
              <div className="p-4 bg-muted rounded-md font-mono text-xs break-all">
                {result.ciphertext}
              </div>
            </div>
            
            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wider text-muted-foreground">
                Key (Hex)
              </Label>
              <div className="p-4 bg-muted rounded-md font-mono text-xs break-all">
                {result.key}
              </div>
            </div>

            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wider text-muted-foreground">
                Hash SHA256 của Key
              </Label>
              <div className="p-4 bg-muted rounded-md font-mono text-xs break-all">
                {result.keyHash}
              </div>
            </div>

            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wider text-muted-foreground">
                Xem Trước Phép XOR
              </Label>
              <div className="p-4 bg-muted rounded-md font-mono text-xs text-muted-foreground">
                {xorVisualization(plaintext, result.key)}
              </div>
            </div>
          </div>
        )}

        {!result && plaintext && !encryptMutation.isPending && (
          <div className="p-4 bg-muted/50 rounded-md text-sm text-muted-foreground">
            Click "Mã Hóa với OTP" to see the encryption results and XOR visualization
          </div>
        )}
      </CardContent>
    </Card>
  );
}
