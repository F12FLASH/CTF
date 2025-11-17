import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Zap, Loader2, Download } from "lucide-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export function ChallengeGenerator() {
  const [count, setCount] = useState("1000");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const generateMutation = useMutation({
    mutationFn: async (count: number) => {
      return apiRequest("POST", "/api/challenge/generate", { count });
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/ciphertexts"] });
      toast({
        title: "Tạo Thành Công",
        description: `Đã tạo ${data.count} bản mã cho thử thách.`,
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Tạo Thất Bại",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleGenerate = () => {
    const num = parseInt(count);
    if (isNaN(num) || num < 1 || num > 1000) {
      toast({
        title: "Giá Trị Không Hợp Lệ",
        description: "Vui lòng nhập số từ 1 đến 1000",
        variant: "destructive",
      });
      return;
    }
    generateMutation.mutate(num);
  };

  const handleDownload = () => {
    window.open("/api/ciphertexts/download", "_blank");
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Zap className="h-5 w-5 text-primary" />
          Tạo Dữ Liệu Thử Thách
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="count" className="text-xs uppercase tracking-wider">
            Số Lượng Bản Mã
          </Label>
          <Input
            id="count"
            type="number"
            min="1"
            max="1000"
            value={count}
            onChange={(e) => setCount(e.target.value)}
            className="font-mono"
            disabled={generateMutation.isPending}
            data-testid="input-challenge-count"
          />
          <p className="text-xs text-muted-foreground">
            Tạo từ 1 đến 1000 bản mã được mã hóa với cùng key (tối đa 1000)
          </p>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Button
            onClick={handleGenerate}
            disabled={generateMutation.isPending}
            className="w-full"
            data-testid="button-generate-challenge"
          >
            {generateMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {generateMutation.isPending ? "Đang Tạo..." : "Tạo Bản Mã"}
          </Button>

          <Button
            onClick={handleDownload}
            variant="secondary"
            className="w-full gap-2"
            data-testid="button-download-ciphertexts"
          >
            <Download className="h-4 w-4" />
            Tải Xuống
          </Button>
        </div>

        <div className="p-4 bg-muted/50 rounded-md space-y-2 text-sm">
          <p className="font-medium">Thông Tin Thử Thách:</p>
          <ul className="text-xs text-muted-foreground space-y-1 list-disc list-inside">
            <li>Plaintext chứa flag: VNFLAG{'{...}'}</li>
            <li>Key được tạo từ: SHA256(flag)</li>
            <li>Tất cả bản mã dùng cùng key và plaintext</li>
            <li>Sử dụng phân tích thống kê để khôi phục flag</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
