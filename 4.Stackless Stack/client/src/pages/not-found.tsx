import { Card, CardContent } from "@/components/ui/card";
import { AlertCircle } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-background">
      <Card className="w-full max-w-md mx-4">
        <CardContent className="pt-6">
          <div className="flex mb-4 gap-2">
            <AlertCircle className="h-8 w-8 text-destructive" />
            <h1 className="text-2xl font-bold font-orbitron text-foreground">404 Không Tìm Thấy Trang</h1>
          </div>

          <p className="mt-4 text-sm text-muted-foreground font-jetbrains">
            Trang bạn đang tìm kiếm không tồn tại.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
