import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { flagSubmissionSchema, type FlagSubmission } from "@shared/schema";
import { apiRequest } from "@/lib/queryClient";
import { CheckCircle2, XCircle, Flag, Loader2 } from "lucide-react";
import confetti from "canvas-confetti";

interface SubmissionResponse {
  correct: boolean;
  message: string;
}

export function FlagSubmissionForm() {
  const { toast } = useToast();
  const [isCorrect, setIsCorrect] = useState<boolean | null>(null);

  const form = useForm<FlagSubmission>({
    resolver: zodResolver(flagSubmissionSchema),
    defaultValues: {
      flag: "",
    },
  });

  const submitMutation = useMutation<SubmissionResponse, Error, FlagSubmission>({
    mutationFn: async (data: FlagSubmission) => {
      const response = await apiRequest("POST", "/api/submit-flag", data);
      return response.json();
    },
    onSuccess: (result) => {
      setIsCorrect(result.correct);
      
      if (result.correct) {
        // Hiệu ứng confetti khi flag đúng
        confetti({
          particleCount: 150,
          spread: 80,
          origin: { y: 0.6 },
          colors: ['#10b981', '#34d399', '#6ee7b7', '#059669'],
        });
        
        toast({
          title: "🎉 Chúc mừng!",
          description: result.message,
          variant: "default",
        });
        
        // Reset form sau khi submit thành công
        form.reset();
      } else {
        toast({
          title: "❌ Chưa đúng",
          description: result.message,
          variant: "destructive",
        });
      }
    },
    onError: (error) => {
      toast({
        title: "Lỗi",
        description: "Có lỗi xảy ra khi gửi flag. Vui lòng thử lại.",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: FlagSubmission) => {
    submitMutation.mutate(data);
  };

  const handleReset = () => {
    setIsCorrect(null);
    form.reset();
  };

  return (
    <Card className="w-full max-w-md mx-auto border-primary/20 shadow-lg" data-testid="card-flag-submission">
      <CardHeader className="pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10 border border-primary/20 shadow-sm">
            <Flag className="h-6 w-6 text-primary" />
          </div>
          <div className="flex-1">
            <CardTitle className="text-2xl font-bold bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent">
              Nộp Flag
            </CardTitle>
            <CardDescription className="text-sm mt-1">
              Nhập flag bạn tìm được để hoàn thành thử thách
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      
      <CardContent>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            <FormField
              control={form.control}
              name="flag"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-sm font-medium">Flag</FormLabel>
                  <FormControl>
                    <div className="relative">
                      <Input
                        {...field}
                        placeholder="VNFLAG{...}"
                        className="font-mono pr-10 h-11 transition-all focus:ring-2 focus:ring-primary/20"
                        data-testid="input-flag"
                        disabled={submitMutation.isPending}
                      />
                      {isCorrect !== null && (
                        <div className="absolute right-3 top-1/2 -translate-y-1/2">
                          {isCorrect ? (
                            <CheckCircle2 className="h-5 w-5 text-green-600 animate-pulse" />
                          ) : (
                            <XCircle className="h-5 w-5 text-red-600 animate-bounce" />
                          )}
                        </div>
                      )}
                    </div>
                  </FormControl>
                  <FormMessage className="text-xs" />
                </FormItem>
              )}
            />
            
            <div className="flex gap-3">
              <Button
                type="button"
                variant="outline"
                onClick={handleReset}
                disabled={submitMutation.isPending}
                className="flex-1"
              >
                Reset
              </Button>
              <Button
                type="submit"
                disabled={submitMutation.isPending || !form.formState.isDirty}
                className="flex-1 bg-primary hover:bg-primary/90 transition-colors"
                data-testid="button-submit-flag"
              >
                {submitMutation.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                    Đang kiểm tra...
                  </>
                ) : (
                  "Nộp Flag"
                )}
              </Button>
            </div>
            
            {/* Status indicator */}
            {isCorrect !== null && (
              <div className={`p-3 rounded-lg text-sm font-medium text-center ${
                isCorrect 
                  ? "bg-green-50 text-green-700 border border-green-200" 
                  : "bg-red-50 text-red-700 border border-red-200"
              }`}>
                {isCorrect ? "✅ Flag chính xác!" : "❌ Flag không chính xác"}
              </div>
            )}
          </form>
        </Form>
      </CardContent>
    </Card>
  );
}