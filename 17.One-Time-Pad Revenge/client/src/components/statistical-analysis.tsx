import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { BarChart3, Hash, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { StatisticalAnalysis as StatisticalAnalysisType } from "@shared/schema";

export function StatisticalAnalysis() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery<StatisticalAnalysisType>({
    queryKey: ["/api/analysis/statistical"],
    retry: false,
  });

  const analyzeMutation = useMutation({
    mutationFn: async () => {
      return apiRequest<StatisticalAnalysisType>("POST", "/api/analysis/statistical", {});
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/analysis/statistical"] });
      toast({
        title: "Phân Tích Hoàn Tất",
        description: "Phân tích thống kê đã được tạo thành công.",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Phân Tích Thất Bại",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const hasData = !!data && data.totalCiphertexts > 0;
  const isError = !!error && !isLoading;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="font-display text-3xl font-semibold">Phân Tích Thống Kê</h2>
        <Button
          onClick={() => analyzeMutation.mutate()}
          disabled={analyzeMutation.isPending || isLoading}
          variant="secondary"
          data-testid="button-run-statistical-analysis"
        >
          {analyzeMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          {analyzeMutation.isPending ? "Đang Phân Tích..." : "Chạy Phân Tích"}
        </Button>
      </div>

      <div className="grid lg:grid-cols-4 gap-6">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
              Tổng Số Bản Mã
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold font-mono">
                {data?.totalCiphertexts || 0}
              </span>
              <span className="text-sm text-muted-foreground">/ 1000</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
              Độ Dài Key
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold font-mono">
                {data?.keyLength || 0}
              </span>
              <span className="text-sm text-muted-foreground">bytes</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
              Điểm Entropy
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold font-mono">
                {data?.entropy ? data.entropy.toFixed(3) : "0.000"}
              </span>
              <span className="text-sm text-muted-foreground">bits</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
              Giá Trị Byte TB
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold font-mono">
                {data?.averageByteValue ? data.averageByteValue.toFixed(2) : "0.00"}
              </span>
              <span className="text-sm text-muted-foreground">/ 255</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {!hasData && !isLoading && !analyzeMutation.isPending ? (
        <Card>
          <CardContent className="py-16">
            <div className="text-center text-muted-foreground space-y-3">
              <BarChart3 className="h-16 w-16 mx-auto opacity-50" />
              <p className="text-sm">
                Tải lên bản mã và chạy phân tích để xem dữ liệu thống kê
              </p>
              <p className="text-xs">
                Phân bố tần suất, tính toán entropy và nhận dạng mẫu sẽ xuất hiện ở đây
              </p>
            </div>
          </CardContent>
        </Card>
      ) : hasData ? (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Hash className="h-5 w-5 text-primary" />
              Phân Bố Tần Suất Byte (32 vị trí đầu)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="h-64 flex items-end gap-1 p-4 bg-muted rounded-md">
                {data.byteFrequency && data.byteFrequency.slice(0, 32).map((freq, i) => {
                  const totalCount = Object.values(freq).reduce((a, b) => a + b, 0);
                  const height = Math.min((totalCount / data.totalCiphertexts) * 100, 100);
                  const topByte = Object.entries(freq).sort((a, b) => b[1] - a[1])[0];
                  
                  return (
                    <div
                      key={i}
                      className="flex-1 bg-primary rounded-sm transition-all hover:bg-primary/80 cursor-pointer"
                      style={{ height: `${height}%` }}
                      title={`Vị trí ${i}: 0x${topByte?.[0] || "00"} (${topByte?.[1] || 0} lần)`}
                    />
                  );
                })}
              </div>
              <div className="flex justify-between text-xs font-mono text-muted-foreground">
                <span>Vị trí 0</span>
                <span>Vị trí 16</span>
                <span>Vị trí 32</span>
              </div>
            </div>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
