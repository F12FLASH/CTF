import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Flag, X, CheckCircle, XCircle } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import type { FlagSubmission, FlagResponse } from "@shared/schema";

interface FlagModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function FlagModal({ isOpen, onClose }: FlagModalProps) {
  const [flag, setFlag] = useState("");
  const { toast } = useToast();

  const submitMutation = useMutation({
    mutationFn: async (data: FlagSubmission) => {
      const res = await apiRequest("POST", "/api/submit-flag", data);
      return await res.json() as FlagResponse;
    },
    onSuccess: (data) => {
      if (data.success) {
        toast({
          title: "Đã Bắt Flag!",
          description: data.message,
        });
        setFlag("");
        setTimeout(onClose, 2000);
      } else {
        toast({
          title: "Flag Không Hợp Lệ",
          description: data.message,
          variant: "destructive",
        });
      }
    },
    onError: (error: Error) => {
      toast({
        title: "Nộp Thất Bại",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (flag.trim()) {
      submitMutation.mutate({ flag: flag.trim() });
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-md border-primary/30 bg-card" data-testid="modal-flag">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-xl">
            <Flag className="w-5 h-5 text-primary" />
            Nộp Flag
          </DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="flag" className="text-sm font-medium">
              Nhập flag đã bắt được
            </Label>
            <Input
              id="flag"
              value={flag}
              onChange={(e) => setFlag(e.target.value)}
              placeholder="VNFLAG{...}"
              className="font-mono"
              disabled={submitMutation.isPending}
              data-testid="input-flag"
            />
            <p className="text-xs text-muted-foreground">
              Định dạng flag bắt đầu với <code className="font-mono bg-muted px-1 py-0.5 rounded">VNFLAG&#123;</code>
            </p>
          </div>

          {submitMutation.isSuccess && submitMutation.data && (
            <div className={`p-4 rounded-md border flex items-start gap-3 ${
              submitMutation.data.success
                ? 'bg-primary/10 border-primary/30'
                : 'bg-destructive/10 border-destructive/30'
            }`}>
              {submitMutation.data.success ? (
                <CheckCircle className="w-5 h-5 text-primary mt-0.5" />
              ) : (
                <XCircle className="w-5 h-5 text-destructive mt-0.5" />
              )}
              <div className="flex-1">
                <p className={`text-sm font-semibold ${
                  submitMutation.data.success ? 'text-primary-foreground' : 'text-destructive-foreground'
                }`}>
                  {submitMutation.data.success ? 'Thành Công!' : 'Không Chính Xác'}
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  {submitMutation.data.message}
                </p>
              </div>
            </div>
          )}

          <div className="flex gap-2 justify-end">
            <Button
              type="button"
              variant="outline"
              onClick={onClose}
              disabled={submitMutation.isPending}
              data-testid="button-cancel"
            >
              <X className="w-4 h-4 mr-2" />
              Hủy
            </Button>
            <Button
              type="submit"
              disabled={submitMutation.isPending || !flag.trim()}
              data-testid="button-submit"
            >
              <Flag className="w-4 h-4 mr-2" />
              {submitMutation.isPending ? 'Đang Nộp...' : 'Nộp Flag'}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
