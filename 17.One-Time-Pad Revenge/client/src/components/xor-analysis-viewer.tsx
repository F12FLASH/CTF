import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { GitCompare, ChevronDown, ChevronRight, Loader2 } from "lucide-react";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { XorAnalysis } from "@shared/schema";

export function XorAnalysisViewer() {
  const [expandedPairs, setExpandedPairs] = useState<Set<string>>(new Set());
  const [index1, setIndex1] = useState("0");
  const [index2, setIndex2] = useState("1");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: analyses = [] } = useQuery<XorAnalysis[]>({
    queryKey: ["/api/analysis/xor"],
  });

  const analyzeMutation = useMutation({
    mutationFn: async (data: { index1: number; index2: number }) => {
      return apiRequest<XorAnalysis>("POST", "/api/analysis/xor", data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/analysis/xor"] });
      toast({
        title: "Phân Tích XOR Hoàn Tất",
        description: "Cặp bản mã đã được phân tích thành công.",
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

  const togglePair = (id: string) => {
    setExpandedPairs((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  };

  const formatHexDump = (hex: string) => {
    const bytes = hex.match(/.{1,2}/g) || [];
    const lines: string[] = [];
    
    for (let i = 0; i < Math.min(bytes.length, 256); i += 16) {
      const lineBytes = bytes.slice(i, i + 16);
      const address = i.toString(16).padStart(8, "0").toUpperCase();
      const hexPart = lineBytes.map(b => b.toUpperCase()).join(" ");
      lines.push(`${address}  ${hexPart}`);
    }
    
    return lines;
  };

  const handleRunAnalysis = () => {
    const i1 = parseInt(index1);
    const i2 = parseInt(index2);
    
    if (isNaN(i1) || isNaN(i2)) {
      toast({
        title: "Đầu Vào Không Hợp Lệ",
        description: "Vui lòng nhập chỉ số bản mã hợp lệ.",
        variant: "destructive",
      });
      return;
    }
    
    analyzeMutation.mutate({ index1: i1, index2: i2 });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <GitCompare className="h-5 w-5 text-primary" />
          Phân Tích Cặp XOR
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label htmlFor="index1" className="text-xs uppercase tracking-wider">
              Chỉ Số Bản Mã 1
            </Label>
            <Input
              id="index1"
              type="number"
              min="0"
              value={index1}
              onChange={(e) => setIndex1(e.target.value)}
              className="font-mono"
              data-testid="input-xor-index1"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="index2" className="text-xs uppercase tracking-wider">
              Chỉ Số Bản Mã 2
            </Label>
            <Input
              id="index2"
              type="number"
              min="0"
              value={index2}
              onChange={(e) => setIndex2(e.target.value)}
              className="font-mono"
              data-testid="input-xor-index2"
            />
          </div>
        </div>

        <Button
          variant="secondary"
          onClick={handleRunAnalysis}
          disabled={analyzeMutation.isPending}
          className="w-full"
          data-testid="button-run-xor-analysis"
        >
          {analyzeMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          {analyzeMutation.isPending ? "Đang Phân Tích..." : "Phân Tích Cặp XOR"}
        </Button>

        {analyses.length === 0 ? (
          <div className="py-16 text-center text-muted-foreground space-y-3 border-t">
            <GitCompare className="h-16 w-16 mx-auto opacity-50" />
            <p className="text-sm">
              Chưa có kết quả phân tích XOR
            </p>
            <p className="text-xs max-w-md mx-auto">
              XOR nhiều cặp bản mã để xác định mẫu trong keystream. 
              Điều này tiết lộ mối tương quan giúp khôi phục khóa mã hóa.
            </p>
          </div>
        ) : (
          <div className="space-y-2 border-t pt-4">
            {analyses.map((pair, idx) => {
              const pairId = `${pair.pairIndex1}-${pair.pairIndex2}`;
              const isExpanded = expandedPairs.has(pairId);
              return (
                <div
                  key={pairId}
                  className="border rounded-md overflow-hidden"
                  data-testid={`xor-pair-${pairId}`}
                >
                  <button
                    onClick={() => togglePair(pairId)}
                    className="w-full p-4 flex items-center justify-between hover-elevate text-left"
                  >
                    <div className="flex items-center gap-3">
                      {isExpanded ? (
                        <ChevronDown className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      )}
                      <span className="font-mono text-sm">
                        CT[{pair.pairIndex1}] ⊕ CT[{pair.pairIndex2}]
                      </span>
                    </div>
                    <Badge variant="secondary" className="font-mono text-xs">
                      {pair.patterns.length} mẫu
                    </Badge>
                  </button>
                  
                  {isExpanded && (
                    <div className="p-4 border-t bg-muted/30">
                      <div className="space-y-2">
                        <div className="text-xs uppercase tracking-wider text-muted-foreground mb-2">
                          Kết Quả XOR (Hex Dump - 256 bytes đầu)
                        </div>
                        <div className="max-h-96 overflow-y-auto bg-card rounded-md p-4 font-mono text-xs">
                          {formatHexDump(pair.xorResult).map((line, i) => (
                            <div
                              key={i}
                              className="hover:bg-muted/50 px-2 -mx-2 rounded"
                            >
                              {line}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
