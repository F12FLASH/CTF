import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { FileCode, Star, AlertCircle } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useQuery } from "@tanstack/react-query";
import type { Template } from "@shared/schema";
import { Skeleton } from "@/components/ui/skeleton";
import { useLanguage } from "@/components/app-sidebar";
import { Alert, AlertDescription } from "@/components/ui/alert";

export default function Templates() {
  const { lang } = useLanguage();
  const [selectedTemplate, setSelectedTemplate] = useState<Template | null>(null);

  const { data: templates = [], isLoading, error } = useQuery<Template[]>({
    queryKey: ["/api/templates"],
  });

  return (
    <div className="p-4 lg:p-6 space-y-4 lg:space-y-6 h-full overflow-y-auto">
      <div className="space-y-2">
        <h1 className="text-2xl font-bold">
          {lang === "vi" ? "Mẫu Exploit" : "Exploit Templates"}
        </h1>
        <p className="text-sm text-muted-foreground">
          {lang === "vi"
            ? "Mẫu được cấu hình sẵn cho thử thách The Phoenix"
            : "Pre-configured templates for The Phoenix challenge"}
        </p>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>
            {lang === "vi" 
              ? "Không thể tải mẫu. Vui lòng thử lại."
              : "Failed to load templates. Please try again."}
          </AlertDescription>
        </Alert>
      )}

      {isLoading ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 lg:gap-6">
          {[...Array(2)].map((_, i) => (
            <Skeleton key={i} className="h-96" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 lg:gap-6">
          {templates.map((template) => (
            <Card key={template.id} className="p-4 lg:p-6 space-y-4 hover-elevate">
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-1 flex-1">
                    <h3 className="text-lg font-semibold">{template.name}</h3>
                    <p className="text-sm text-muted-foreground">
                      {lang === "vi" ? template.descriptionVi : template.description}
                    </p>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    {Array.from({ length: template.difficulty }).map((_, i) => (
                      <Star
                        key={i}
                        className="h-3 w-3 fill-primary text-primary"
                      />
                    ))}
                  </div>
                </div>
                <Badge variant="secondary" className="text-xs">
                  {template.category}
                </Badge>
              </div>

              <div className="bg-muted p-3 rounded font-mono text-xs overflow-x-auto max-h-32 overflow-y-auto">
                {template.code.split("\n").slice(0, 10).join("\n")}
                {template.code.split("\n").length > 10 && "\n..."}
              </div>

              <Dialog>
                <DialogTrigger asChild>
                  <Button
                    variant="outline"
                    className="w-full gap-2"
                    onClick={() => setSelectedTemplate(template)}
                    data-testid={`button-view-template-${template.id}`}
                  >
                    <FileCode className="h-4 w-4" />
                    {lang === "vi" ? "Xem Toàn Bộ Mẫu" : "View Full Template"}
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-4xl max-h-[80vh]">
                  <DialogHeader>
                    <DialogTitle>{template.name}</DialogTitle>
                    <DialogDescription>
                      {lang === "vi" ? template.descriptionVi : template.description}
                    </DialogDescription>
                  </DialogHeader>
                  <ScrollArea className="h-[60vh]">
                    <div className="space-y-4">
                      <div className="space-y-2">
                        <h4 className="text-sm font-semibold">
                          {lang === "vi" ? "Mã" : "Code"}
                        </h4>
                        <div className="bg-muted p-4 rounded font-mono text-xs overflow-x-auto">
                          <pre>{template.code}</pre>
                        </div>
                      </div>
                      <div className="space-y-2">
                        <h4 className="text-sm font-semibold">
                          {lang === "vi" ? "Tài Liệu" : "Documentation"}
                        </h4>
                        <div className="prose prose-sm dark:prose-invert max-w-none">
                          <pre className="whitespace-pre-wrap text-xs">
                            {template.documentationVi}
                          </pre>
                        </div>
                      </div>
                    </div>
                  </ScrollArea>
                </DialogContent>
              </Dialog>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
