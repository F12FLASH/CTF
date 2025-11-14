import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Flag, Trophy, AlertCircle } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

const flagSchema = z.object({
  flag: z.string().min(1, "Flag là bắt buộc").regex(/^VNFLAG\{.+\}$/, "Flag phải có định dạng VNFLAG{...}"),
});

type FlagFormValues = z.infer<typeof flagSchema>;

export function FlagValidation() {
  const [isCorrect, setIsCorrect] = useState<boolean | null>(null);
  const { toast } = useToast();

  const form = useForm<FlagFormValues>({
    resolver: zodResolver(flagSchema),
    defaultValues: {
      flag: "",
    },
  });

  const validateFlagMutation = useMutation({
    mutationFn: async (data: FlagFormValues) => {
      const response = await apiRequest("POST", "/api/flag/validate", data);
      return await response.json();
    },
    onSuccess: (data: any) => {
      setIsCorrect(data.valid);
      if (data.valid) {
        toast({
          title: "Chúc mừng!",
          description: data.message || "Bạn đã hoàn thành thử thách thành công!",
        });
      } else {
        toast({
          title: "Flag không chính xác",
          description: data.message || "Flag không đúng. Hãy tiếp tục thử!",
          variant: "destructive",
        });
      }
    },
    onError: (error: Error) => {
      toast({
        title: "Xác thực thất bại",
        description: error.message || "Không thể xác thực flag.",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: FlagFormValues) => {
    validateFlagMutation.mutate(data);
  };

  return (
    <Card data-testid="card-flag-validation">
      <CardHeader className="space-y-1">
        <div className="flex items-center gap-2">
          <div className="flex items-center justify-center w-8 h-8 rounded-md bg-primary/10">
            <Flag className="w-4 h-4 text-primary" data-testid="icon-flag" />
          </div>
          <CardTitle className="text-lg" data-testid="title-flag-validation">Xác Thực Flag</CardTitle>
        </div>
        <CardDescription data-testid="text-flag-description">
          Gửi flag bạn tìm được trong cookie đã capture
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-4">
        {isCorrect === true && (
          <div className="p-4 rounded-md bg-status-online/10 border border-status-online/20" data-testid="success-message">
            <div className="flex items-start gap-3">
              <div className="flex items-center justify-center w-10 h-10 rounded-full bg-status-online/20">
                <Trophy className="w-5 h-5 text-status-online" />
              </div>
              <div className="flex-1">
                <p className="text-sm font-medium text-status-online mb-1">
                  Hoàn Thành Thử Thách!
                </p>
                <p className="text-xs text-status-online/80 leading-relaxed">
                  Xuất sắc! Bạn đã khai thác thành công lỗ hổng DOM XSS và
                  capture được cookie admin chứa flag.
                </p>
              </div>
            </div>
          </div>
        )}

        {isCorrect === false && (
          <div className="p-4 rounded-md bg-destructive/10 border border-destructive/20" data-testid="error-message">
            <div className="flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-destructive mt-0.5" />
              <div className="flex-1">
                <p className="text-sm font-medium text-destructive mb-1">
                  Flag Không Chính Xác
                </p>
                <p className="text-xs text-destructive/80 leading-relaxed">
                  Đây không phải flag đúng. Hãy đảm bảo bạn đã capture cookie admin
                  và trích xuất đúng giá trị flag.
                </p>
              </div>
            </div>
          </div>
        )}

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="flag"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Flag</FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      placeholder="VNFLAG{...}"
                      className="font-mono text-sm"
                      data-testid="input-flag"
                    />
                  </FormControl>
                  <FormDescription>
                    Định dạng: <code className="px-1.5 py-0.5 rounded bg-muted text-primary font-mono text-xs">
                      VNFLAG&#123;...&#125;
                    </code>
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <Button
              type="submit"
              disabled={validateFlagMutation.isPending}
              className="w-full gap-2"
              data-testid="button-validate-flag"
            >
              <Flag className="w-4 h-4" />
              {validateFlagMutation.isPending ? "Đang xác thực..." : "Xác Thực Flag"}
            </Button>
          </form>
        </Form>

        <div className="p-3 rounded-md bg-muted/50 border">
          <p className="text-xs text-muted-foreground leading-relaxed">
            Flag được ẩn trong cookie của admin. Hãy khai thác thành công lỗ hổng XSS
            để capture nó.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
