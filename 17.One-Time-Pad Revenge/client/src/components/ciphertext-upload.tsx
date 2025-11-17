import { useCallback, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Upload, FileText, Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { Ciphertext } from "@shared/schema";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";

export function CiphertextUpload() {
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [manualInput, setManualInput] = useState("");
  const [isDragging, setIsDragging] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: ciphertexts = [] } = useQuery<Ciphertext[]>({
    queryKey: ["/api/ciphertexts"],
  });

  const uploadMutation = useMutation({
    mutationFn: async (data: string) => {
      const cleanData = data.replace(/\s+/g, "").trim();
      return apiRequest("POST", "/api/ciphertexts/upload", { data: cleanData });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ciphertexts"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Tải Lên Thất Bại",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const clearMutation = useMutation({
    mutationFn: async () => {
      return apiRequest("DELETE", "/api/ciphertexts", {});
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ciphertexts"] });
      setSelectedFiles([]);
      setManualInput("");
      toast({
        title: "Đã Xóa Bản Mã",
        description: "Tất cả bản mã đã được xóa.",
      });
    },
  });

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    
    const droppedFiles = Array.from(e.dataTransfer.files);
    setSelectedFiles(droppedFiles.slice(0, 1000));
  }, []);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const files = Array.from(e.target.files);
      setSelectedFiles(files.slice(0, 1000));
    }
  };

  const handleUploadFiles = async () => {
    let successCount = 0;
    let failedCount = 0;
    for (const file of selectedFiles) {
      const text = await file.text();
      try {
        await uploadMutation.mutateAsync(text);
        successCount++;
      } catch (err) {
        failedCount++;
      }
    }
    setSelectedFiles([]);
    if (successCount > 0) {
      toast({
        title: "Tải Lên Hoàn Tất",
        description: `Đã tải lên thành công ${successCount} file bản mã.`,
      });
    }
  };

  const handleUploadManual = async () => {
    const cleanInput = manualInput.replace(/\s+/g, "").trim();
    if (!cleanInput) return;
    
    try {
      await uploadMutation.mutateAsync(cleanInput);
      setManualInput("");
      toast({
        title: "Tải Lên Hoàn Tất",
        description: "Đã thêm bản mã thành công.",
      });
    } catch (err) {
      // Error handled by mutation onError
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5 text-primary" />
            <span>Tải Lên Bản Mã</span>
          </CardTitle>
          {ciphertexts.length > 0 && (
            <Badge variant="secondary" className="font-mono">
              {ciphertexts.length} / 1000
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label className="text-xs uppercase tracking-wider">
            Nhập Thủ Công (Hex)
          </Label>
          <Textarea
            placeholder="Nhập bản mã dạng hex (vd: 4a8b2e3f...)"
            value={manualInput}
            onChange={(e) => setManualInput(e.target.value)}
            className="h-24 font-mono text-sm resize-none"
            data-testid="textarea-manual-input"
          />
          <p className="text-xs text-muted-foreground">
            Khoảng trắng sẽ tự động được loại bỏ
          </p>
          <Button
            onClick={handleUploadManual}
            disabled={!manualInput.trim() || uploadMutation.isPending}
            size="sm"
            className="w-full"
            data-testid="button-upload-manual"
          >
            {uploadMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Thêm Bản Mã
          </Button>
        </div>

        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <span className="w-full border-t" />
          </div>
          <div className="relative flex justify-center text-xs uppercase">
            <span className="bg-card px-2 text-muted-foreground">Hoặc</span>
          </div>
        </div>

        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`
            min-h-32 border-2 border-dashed rounded-md
            flex flex-col items-center justify-center gap-3 p-6
            transition-colors cursor-pointer relative
            ${isDragging 
              ? "border-primary bg-primary/5" 
              : "border-border hover:border-primary/50"
            }
          `}
          data-testid="dropzone-ciphertext"
        >
          <Upload className={`h-10 w-10 ${isDragging ? "text-primary" : "text-muted-foreground"}`} />
          <div className="text-center">
            <p className="text-sm font-medium mb-1">
              Kéo thả file vào đây
            </p>
            <p className="text-xs text-muted-foreground">
              hoặc click để chọn
            </p>
          </div>
          <input
            type="file"
            multiple
            onChange={handleFileSelect}
            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
            accept=".txt,.bin,.hex"
            data-testid="input-file-upload"
          />
        </div>

        {selectedFiles.length > 0 && (
          <>
            <div className="text-xs uppercase tracking-wider text-muted-foreground">
              File Đã Chọn ({selectedFiles.length})
            </div>
            
            <Button 
              className="w-full"
              onClick={handleUploadFiles}
              disabled={uploadMutation.isPending}
              data-testid="button-upload-files"
            >
              {uploadMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {uploadMutation.isPending ? "Đang Tải Lên..." : `Tải Lên ${selectedFiles.length} File`}
            </Button>
          </>
        )}

        {ciphertexts.length > 0 && (
          <>
            <div className="flex items-center justify-between pt-2 border-t">
              <div className="text-xs uppercase tracking-wider text-muted-foreground">
                Bản Mã Đã Tải Lên
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => clearMutation.mutate()}
                disabled={clearMutation.isPending}
                data-testid="button-clear-all"
              >
                Xóa Tất Cả
              </Button>
            </div>
            
            <div className="max-h-64 overflow-y-auto space-y-2">
              {ciphertexts.slice(0, 10).map((ct, index) => (
                <div
                  key={ct.id}
                  className="flex items-center gap-3 p-3 bg-muted rounded-md"
                  data-testid={`file-item-${ct.id}`}
                >
                  <FileText className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-mono truncate">Bản Mã #{index + 1}</p>
                    <p className="text-xs text-muted-foreground">
                      {ct.size} bytes ({(ct.size / 2)} ký tự hex)
                    </p>
                  </div>
                </div>
              ))}
              {ciphertexts.length > 10 && (
                <div className="text-center text-sm text-muted-foreground py-2">
                  ...và {ciphertexts.length - 10} bản mã khác
                </div>
              )}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
