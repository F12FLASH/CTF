import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import { Flag, CheckCircle2, XCircle } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useState } from "react";

const flagSubmissionSchema = z.object({
  submittedFlag: z.string().min(1, "Flag is required").trim(),
});

type FlagSubmissionForm = z.infer<typeof flagSubmissionSchema>;

export function FlagSubmission() {
  const [result, setResult] = useState<{ success: boolean; message: string } | null>(null);
  const { toast } = useToast();

  const form = useForm<FlagSubmissionForm>({
    resolver: zodResolver(flagSubmissionSchema),
    defaultValues: {
      submittedFlag: "",
    },
  });

  const submitMutation = useMutation({
    mutationFn: async (data: FlagSubmissionForm) => {
      return await apiRequest("POST", "/api/flag/submit", data);
    },
    onSuccess: (data: any) => {
      setResult({
        success: data.success,
        message: data.message,
      });
      
      if (data.success) {
        toast({
          title: "Congratulations!",
          description: data.message,
        });
        form.reset();
      } else {
        toast({
          variant: "destructive",
          title: "Incorrect Flag",
          description: data.message,
        });
      }
    },
    onError: () => {
      const errorMsg = "Có lỗi xảy ra. Vui lòng thử lại.";
      setResult({
        success: false,
        message: errorMsg,
      });
      toast({
        variant: "destructive",
        description: errorMsg,
      });
    },
  });

  const onSubmit = (data: FlagSubmissionForm) => {
    setResult(null);
    submitMutation.mutate(data);
  };

  return (
    <Card className="border rounded-lg" data-testid="card-flag-submission">
      <CardHeader className="p-6">
        <div className="flex items-center gap-3">
          <Flag className="w-6 h-6 text-primary" />
          <CardTitle className="text-xl">Submit Flag</CardTitle>
        </div>
        <p className="text-sm text-muted-foreground mt-2">
          Enter the flag you've discovered
        </p>
      </CardHeader>
      <CardContent className="p-6 pt-0">
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="submittedFlag"
              render={({ field }) => (
                <FormItem>
                  <FormControl>
                    <Input
                      placeholder="VNFLAG{...}"
                      className="text-base font-mono"
                      disabled={submitMutation.isPending}
                      data-testid="input-flag"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button
              type="submit"
              className="w-full"
              disabled={submitMutation.isPending}
              data-testid="button-submit-flag"
            >
              {submitMutation.isPending ? "Submitting..." : "Submit Flag"}
            </Button>
          </form>
        </Form>

        {result && (
          <div
            className={`mt-4 p-4 border rounded-md flex items-start gap-3 ${
              result.success
                ? "border-green-500/50 bg-green-500/10"
                : "border-red-500/50 bg-red-500/10"
            }`}
            data-testid="submission-result"
          >
            {result.success ? (
              <CheckCircle2 className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />
            ) : (
              <XCircle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
            )}
            <p className={`text-sm font-medium ${
              result.success
                ? "text-green-700 dark:text-green-300"
                : "text-red-700 dark:text-red-300"
            }`}>
              {result.message}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
