import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Download, FileCode, AlertTriangle } from "lucide-react";
import { Badge } from "@/components/ui/badge";

export function BinaryDownload() {
  const handleDownload = () => {
    window.open("/api/download-binary", "_blank");
  };

  return (
    <Card className="border-primary/20" data-testid="card-binary-download">
      <CardHeader>
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10 border border-primary/20">
            <FileCode className="h-5 w-5 text-primary" />
          </div>
          <div>
            <CardTitle className="text-xl">Tải Binary</CardTitle>
            <CardDescription>Tải xuống binary "the_joker" để bắt đầu thử thách</CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-lg bg-muted/50 p-4 border border-border">
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Tên file:</span>
              <span className="font-mono">the_joker</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Loại:</span>
              <Badge variant="secondary" className="font-mono text-2xs">ELF 64-bit</Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Độ khó:</span>
              <Badge variant="secondary" className="font-mono text-2xs">Expert (4/4)</Badge>
            </div>
          </div>
        </div>

        <div className="flex items-start gap-2 p-3 rounded-md bg-destructive/10 border border-destructive/20">
          <AlertTriangle className="h-4 w-4 text-destructive flex-shrink-0 mt-0.5" />
          <div className="text-xs text-destructive space-y-1">
            <p className="font-semibold">Cảnh báo bảo mật</p>
            <p>Binary này chứa kỹ thuật anti-debugging và self-modifying code. Chỉ chạy trong môi trường sandbox hoặc máy ảo.</p>
          </div>
        </div>

        <Button
          onClick={handleDownload}
          className="w-full gap-2"
          data-testid="button-download-binary"
        >
          <Download className="h-4 w-4" />
          Tải xuống the_joker
        </Button>
      </CardContent>
    </Card>
  );
}
